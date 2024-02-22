package api

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"aead.dev/minisign"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/sliverarmory/external-armory/consts"
)

// ArmoryServer - The armory server object
type ArmoryServer struct {
	HTTPServer         *http.Server
	ArmoryServerConfig *ArmoryServerConfig
	AccessLog          *logrus.Logger
	AppLog             *logrus.Logger
}

type SigningKeyProviderInfo map[string]string

// ArmoryServerConfig - Configuration options for the Armory server
type ArmoryServerConfig struct {
	DomainName string `json:"domain_name"`
	ListenHost string `json:"lhost"`
	ListenPort uint16 `json:"lport"`

	TLSEnabled bool `json:"tls_enabled"`

	RootDir   string `json:"root_dir"`
	PublicKey string `json:"public_key"`

	AuthenticationDisabled   bool   `json:"authentication_disabled"`
	AuthorizationTokenDigest string `json:"authorization_token_digest"`

	WriteTimeout time.Duration `json:"write_timeout"`
	ReadTimeout  time.Duration `json:"read_timeout"`

	SigningKey                *minisign.PrivateKey   `json:"-"`
	SigningKeyProvider        string                 `json:"signing_key_provider"`
	SigningKeyProviderDetails SigningKeyProviderInfo `json:"signing_key_provider_details,omitempty"`
}

// RepoURL - Returns the (most likely) repo URL, if no domain is provided
// we attempt to determine the primary interface IP address.
func (c *ArmoryServerConfig) RepoURL() string {
	scheme := "http"
	if c.TLSEnabled {
		scheme = "https"
	}
	host := c.DomainName
	if host == "" {
		host = c.getOutboundIP()
	}
	repoURL, err := url.Parse(fmt.Sprintf("%s://%s:%d", scheme, host, c.ListenPort))
	if err != nil {
		return ""
	}
	return repoURL.String()
}

func (c *ArmoryServerConfig) getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// ArmoryIndex - Root index, must be signed by server private key
type ArmoryIndex struct {
	Aliases    []*ArmoryEntry  `json:"aliases"`
	Extensions []*ArmoryEntry  `json:"extensions"`
	Bundles    []*ArmoryBundle `json:"bundles"`
}

// ArmoryEntry - An alias or extension entry
type ArmoryEntry struct {
	Name        string `json:"name"`
	CommandName string `json:"command_name"`
	RepoURL     string `json:"repo_url"`
	PublicKey   string `json:"public_key"`
}

// ArmoryBundle - A bundle of packages
type ArmoryBundle struct {
	Name     string   `json:"name"`
	Packages []string `json:"packages"`
}

type armoryIndexResponse struct {
	Minisig     string `json:"minisig"`      // Minisig (Base 64)
	ArmoryIndex string `json:"armory_index"` // Index JSON (Base 64)
}

type armoryPkgResponse struct {
	Minisig  string `json:"minisig"` // Minisig (Base 64)
	TarGzURL string `json:"tar_gz_url"`
}

// JSONError - Return an error in JSON format
type JSONError struct {
	Error string `json:"error"`
}

// New - Create a new server instance with given configuration and loggers
func New(config *ArmoryServerConfig, app *logrus.Logger, access *logrus.Logger) *ArmoryServer {
	server := &ArmoryServer{
		ArmoryServerConfig: config,
		AccessLog:          access,
		AppLog:             app,
	}
	router := mux.NewRouter()
	router.NotFoundHandler = jsonNotFoundHandler{}
	router.Use(server.defaultHeadersMiddleware)
	router.Use(server.loggingMiddleware)

	// Public Handlers
	router.HandleFunc("/health", server.healthHandler)

	// Armory Handlers
	armoryRouter := router.PathPrefix("/armory").Subrouter()
	if !server.ArmoryServerConfig.AuthenticationDisabled {
		server.AppLog.Infof("Authentication is enabled")
		armoryRouter.Use(server.authorizationTokenMiddleware)
	} else {
		server.AppLog.Infof("Authentication is disabled")
	}
	armoryRouter.Use(server.versionHeaderMiddleware)

	// /armory/index
	armoryRouter.HandleFunc("/index", server.IndexHandler).Methods(http.MethodGet)
	// /armory/aliases/<alias_name> (Get the link to the archive and the signature)
	armoryRouter.HandleFunc(
		fmt.Sprintf("/%s/{%s}", consts.AliasesDirName, consts.AliasPathVariable),
		server.AliasMetaHandler).Methods(http.MethodGet)
	// /armory/aliases/archive/<alias_name> (Get the package itself)
	armoryRouter.HandleFunc(
		fmt.Sprintf("/%s/%s/{%s}", consts.AliasesDirName, consts.ArchivePathName, consts.AliasPathVariable),
		server.AliasArchiveHandler).Methods(http.MethodGet)
	// /armory/extensions/<extension_name> (Get the link to the archive and the signature)
	armoryRouter.HandleFunc(
		fmt.Sprintf("/%s/{%s}", consts.ExtensionsDirName, consts.ExtensionPathVariable),
		server.ExtensionMetaHandler).Methods(http.MethodGet)
	// /armory/extensions/archive/<extension_name> (Get the package itself)
	armoryRouter.HandleFunc(
		fmt.Sprintf("/%s/%s/{%s}", consts.ExtensionsDirName, consts.ArchivePathName, consts.ExtensionPathVariable),
		server.ExtensionArchiveHandler).Methods(http.MethodGet)

	server.HTTPServer = &http.Server{
		Handler:      router,
		Addr:         fmt.Sprintf("%s:%d", config.ListenHost, config.ListenPort),
		WriteTimeout: config.WriteTimeout,
		ReadTimeout:  config.ReadTimeout,
	}
	if server.ArmoryServerConfig.TLSEnabled {
		server.HTTPServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	return server
}

// --------------
// Handlers
// --------------

type jsonNotFoundHandler struct{}

func (jsonNotFoundHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
	resp.Header().Set("X-Frame-Options", "deny")
	resp.WriteHeader(http.StatusNotFound)
	resp.Write([]byte{})
}

// IndexHandler - Returns the index of extensions, aliases, and bundles
func (s *ArmoryServer) IndexHandler(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")
	index, sig := s.getIndex()
	data, _ := json.Marshal(&armoryIndexResponse{
		Minisig:     base64.StdEncoding.EncodeToString(sig),
		ArmoryIndex: base64.StdEncoding.EncodeToString(index),
	})
	resp.WriteHeader(http.StatusOK)
	resp.Write(data)
}

func (s *ArmoryServer) getIndex() ([]byte, []byte) {
	indexPath := filepath.Join(s.ArmoryServerConfig.RootDir, consts.ArmoryIndexFileName)
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		s.AppLog.Errorf("Error reading index: %s", err)
		return nil, nil
	}
	indexSigPath := filepath.Join(s.ArmoryServerConfig.RootDir, consts.ArmoryIndexSigFileName)
	sigData, err := os.ReadFile(indexSigPath)
	if err != nil {
		s.AppLog.Errorf("Error reading index: %s", err)
		return nil, nil
	}
	return indexData, sigData
}

func (s *ArmoryServer) getPackageData(packageName string, isAlias bool) ([]byte, error) {
	sigPath := filepath.Join(s.ArmoryServerConfig.RootDir, consts.SignaturesDirName, packageName)
	// Check the path
	if _, err := os.Stat(sigPath); errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, fmt.Errorf("could not read sig file for package %s: %s", packageName, err)
	}

	pkgType := ""
	if isAlias {
		pkgType = consts.AliasesDirName
	} else {
		pkgType = consts.ExtensionsDirName
	}

	pkgData := armoryPkgResponse{
		Minisig:  base64.StdEncoding.EncodeToString(sigData),
		TarGzURL: fmt.Sprintf("%s/armory/%s/%s/%s", s.ArmoryServerConfig.RepoURL(), pkgType, consts.ArchivePathName, packageName),
	}

	return json.Marshal(&pkgData)
}

// AliasMetaHandler - returns the signature of the package and a link to it as JSON
func (s *ArmoryServer) AliasMetaHandler(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")
	vars := mux.Vars(req)
	requestedAlias, ok := vars[consts.AliasPathVariable]
	if !ok {
		s.jsonError(resp, fmt.Errorf("could not find alias path variable in URL: %s", req.URL.String()))
		return
	}
	pkgData, err := s.getPackageData(requestedAlias, true)
	if err != nil {
		s.jsonError(resp, err)
		return
	}
	resp.WriteHeader(http.StatusOK)
	resp.Write(pkgData)
}

// AliasArchiveHandler - returns the package archive
func (s *ArmoryServer) AliasArchiveHandler(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/octet-stream")
	vars := mux.Vars(req)
	requestedAlias, ok := vars[consts.AliasPathVariable]
	if !ok {
		s.jsonError(resp, fmt.Errorf("could not find alias path variable in URL: %s", req.URL.String()))
		return
	}
	fsPath := filepath.Join(s.ArmoryServerConfig.RootDir, consts.AliasesDirName, fmt.Sprintf("%s.tar.gz", requestedAlias))
	archiveData, err := os.ReadFile(fsPath)
	if err != nil {
		s.jsonError(resp, err)
		return
	}
	resp.WriteHeader(http.StatusOK)
	resp.Write(archiveData)
}

// ExtensionMetaHandler - returns the signature of the package and a link to it as JSON
func (s *ArmoryServer) ExtensionMetaHandler(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")
	vars := mux.Vars(req)
	requestedExtension, ok := vars[consts.ExtensionPathVariable]
	if !ok {
		s.jsonError(resp, fmt.Errorf("could not find extension path variable in URL: %s", req.URL.String()))
		return
	}
	pkgData, err := s.getPackageData(requestedExtension, false)
	if err != nil {
		s.jsonError(resp, err)
		return
	}
	resp.WriteHeader(http.StatusOK)
	resp.Write(pkgData)
}

// ExtensionArchiveHandler - returns the package archive
func (s *ArmoryServer) ExtensionArchiveHandler(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/octet-stream")
	vars := mux.Vars(req)
	requestedExtension, ok := vars[consts.ExtensionPathVariable]
	if !ok {
		s.jsonError(resp, fmt.Errorf("could not find extension path variable in URL: %s", req.URL.String()))
		return
	}
	fsPath := filepath.Join(s.ArmoryServerConfig.RootDir, consts.ExtensionsDirName, fmt.Sprintf("%s.tar.gz", requestedExtension))
	archiveData, err := os.ReadFile(fsPath)
	if err != nil {
		s.jsonError(resp, err)
		return
	}
	resp.WriteHeader(http.StatusOK)
	resp.Write(archiveData)
}

// --------------
// Middleware
// --------------

func (s *ArmoryServer) authorizationTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		authHeaderDigest := sha256.Sum256([]byte(req.Header.Get("Authorization")))
		if fmt.Sprintf("%x", authHeaderDigest[:]) == s.ArmoryServerConfig.AuthorizationTokenDigest {
			next.ServeHTTP(resp, req)
		} else {
			s.jsonForbidden(resp, errors.New("user is not authenticated"))
		}
	})
}

func (s *ArmoryServer) defaultHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		resp.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
		resp.Header().Set("X-Frame-Options", "deny")
		next.ServeHTTP(resp, req)
	})
}

func (s *ArmoryServer) versionHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		resp.Header().Set("Armory-API-Version", VersionHeader)
		next.ServeHTTP(resp, req)
	})
}

func (s *ArmoryServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		xForwardedFor := req.Header.Get("X-Forwarded-For")
		if xForwardedFor != "" {
			s.AccessLog.Infof("%s->%s %s %s", xForwardedFor, req.RemoteAddr, req.Method, req.RequestURI)
		} else {
			s.AccessLog.Infof("%s %s %s", req.RemoteAddr, req.Method, req.RequestURI)
		}
		next.ServeHTTP(resp, req)
	})
}

// healthHandler - Simple health check
func (s *ArmoryServer) healthHandler(resp http.ResponseWriter, req *http.Request) {
	resp.WriteHeader(http.StatusOK)
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")
	resp.Write([]byte(`{"health": "ok"}`))
}

func (s *ArmoryServer) jsonError(resp http.ResponseWriter, err error) {
	s.AppLog.Error(err)
	resp.WriteHeader(http.StatusNotFound)
	resp.Write([]byte{})
}

func (s *ArmoryServer) jsonForbidden(resp http.ResponseWriter, err error) {
	resp.WriteHeader(http.StatusNotFound)
	resp.Write([]byte{})
}
