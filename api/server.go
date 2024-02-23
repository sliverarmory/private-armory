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
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"aead.dev/minisign"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/sliverarmory/external-armory/consts"
)

var StatusOKResponse = []byte(`{"status": "ok"}`)

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

	ClientAuthenticationDisabled   bool   `json:"client_authentication_disabled"`
	ClientAuthorizationTokenDigest string `json:"client_authorization_token_digest"`
	AdminAuthorizationTokenDigest  string `json:"admin_authorization_token_digest"`

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
	armoryRouter.Use(server.authorizationTokenMiddleware)
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
	// PUT /armory/<package_type>/<name> (add a new package)
	armoryRouter.HandleFunc(
		fmt.Sprintf("/{%s}/{%s}", consts.PackageTypePathVariable, consts.PackageNamePathVariable),
		server.AddPackageHandler,
	).Methods(http.MethodPut)
	// PATCH /armory/<package_type>/<name> (modify a package)
	armoryRouter.HandleFunc(
		fmt.Sprintf("/{%s}/{%s}", consts.PackageTypePathVariable, consts.PackageNamePathVariable),
		server.ModifyPackageHandler,
	).Methods(http.MethodPatch)
	// DELETE /armory/<package_type>/<name> (delete a package)
	armoryRouter.HandleFunc(
		fmt.Sprintf("/{%s}/{%s}", consts.PackageTypePathVariable, consts.PackageNamePathVariable),
		server.RemovePackageHandler,
	).Methods(http.MethodDelete)

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
	// Make sure the package still exists
	pkgPath := ""
	if isAlias {
		pkgPath = filepath.Join(s.ArmoryServerConfig.RootDir, consts.AliasesDirName, fmt.Sprintf("%s.tar.gz", packageName))
	} else {
		pkgPath = filepath.Join(s.ArmoryServerConfig.RootDir, consts.ExtensionsDirName, fmt.Sprintf("%s.tar.gz", packageName))
	}
	sigPath := filepath.Join(s.ArmoryServerConfig.RootDir, consts.SignaturesDirName, packageName)
	_, err := os.Stat(pkgPath)
	if err != nil {
		// There is something wrong with the package, remove signatures if any exist
		os.Remove(sigPath)
		return nil, fmt.Errorf("attempted to retrieve package %s, but encountered an error: %s", packageName, err)
	}

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

func derivePackagePathAndNameFromRequest(rootDir string, req *http.Request) (string, string, error) {
	vars := mux.Vars(req)

	requestedPackageType, ok := vars[consts.PackageTypePathVariable]
	if !ok {
		return "", "", fmt.Errorf("could not find package type in URL: %s", req.URL.String())
	}
	requestedPackageName, ok := vars[consts.PackageNamePathVariable]
	if !ok {
		return "", "", fmt.Errorf("could not find package name in URL: %s", req.URL.String())
	}

	packagePath := ""
	switch requestedPackageType {
	case consts.AliasesDirName:
		packagePath = consts.AliasesDirName
	case consts.ExtensionsDirName:
		packagePath = consts.ExtensionsDirName
	default:
		return "", "", fmt.Errorf("%s is not a valid package type", requestedPackageType)
	}

	fsPath := filepath.Join(rootDir, packagePath, fmt.Sprintf("%s.tar.gz", requestedPackageName))

	return fsPath, requestedPackageName, nil
}

func writePackageToDisk(packagePath string, requestedPackageName string, requestBody io.ReadCloser) error {
	// When the package is written to disk, the server will automatically refresh the index
	packageData, err := io.ReadAll(requestBody)
	if err != nil {
		return fmt.Errorf("error processing request: %s", err)
	}

	err = os.WriteFile(packagePath, packageData, 0660)
	if err != nil {
		return fmt.Errorf("internal error comitting package %s: %s", requestedPackageName, err)
	}

	return nil
}

func (s *ArmoryServer) AddPackageHandler(resp http.ResponseWriter, req *http.Request) {
	s.AppLog.Infoln("Inside of add")
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")

	defer req.Body.Close()

	fsPath, requestedPackageName, err := derivePackagePathAndNameFromRequest(s.ArmoryServerConfig.RootDir, req)
	if err != nil {
		s.jsonError(resp, err)
		return
	}

	if _, err := os.Stat(fsPath); err == nil {
		s.jsonError(resp, fmt.Errorf("%s already exists", requestedPackageName))
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		// If we have any other error than the file not existing, bail
		s.jsonError(resp, fmt.Errorf("internal error for package %s: %s", requestedPackageName, err))
		return
	}
	// If we get here, the package does not exist
	err = writePackageToDisk(fsPath, requestedPackageName, req.Body)
	if err != nil {
		s.jsonError(resp, err)
		return
	}

	resp.WriteHeader(http.StatusOK)
	resp.Write(StatusOKResponse)
}

func (s *ArmoryServer) ModifyPackageHandler(resp http.ResponseWriter, req *http.Request) {
	s.AppLog.Infoln("Inside of modify")
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")

	defer req.Body.Close()

	fsPath, requestedPackageName, err := derivePackagePathAndNameFromRequest(s.ArmoryServerConfig.RootDir, req)
	if err != nil {
		s.jsonError(resp, err)
		return
	}

	if _, err := os.Stat(fsPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.jsonError(resp, fmt.Errorf("internal error for package %s: %s", requestedPackageName, err))
			return
		}
	}

	// If we are here, then the package exists, and we will overwrite it or it does not exist and we will add it
	err = writePackageToDisk(fsPath, requestedPackageName, req.Body)
	if err != nil {
		s.jsonError(resp, err)
		return
	}
	resp.WriteHeader(http.StatusOK)
	resp.Write(StatusOKResponse)
}

func (s *ArmoryServer) RemovePackageHandler(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")
	s.AppLog.Infoln("Inside of delete")

	fsPath, requestedPackageName, err := derivePackagePathAndNameFromRequest(s.ArmoryServerConfig.RootDir, req)
	if err != nil {
		s.jsonError(resp, err)
		return
	}

	_, err = os.Stat(fsPath)

	if err == nil {
		// The package exists so we can delete it
		err = os.Remove(fsPath)
		if err != nil {
			s.jsonError(resp, fmt.Errorf("internal error while deleting package %s: %s", requestedPackageName, err))
			return
		}
		sigPath := filepath.Join(s.ArmoryServerConfig.RootDir, consts.SignaturesDirName, requestedPackageName)
		err = os.Remove(sigPath)
		if err != nil {
			s.jsonError(resp, fmt.Errorf("internal error while deleting package signature %s: %s", requestedPackageName, err))
			return
		}
		resp.WriteHeader(http.StatusOK)
		resp.Write(StatusOKResponse)
	} else if errors.Is(err, os.ErrNotExist) {
		s.jsonError(resp, fmt.Errorf("package %s does not exist", requestedPackageName))
		return
	} else {
		s.jsonError(resp, fmt.Errorf("internal error for package %s", requestedPackageName))
		return
	}
}

// --------------
// Middleware
// --------------

func (s *ArmoryServer) authorizationTokenMiddleware(next http.Handler) http.Handler {
	// PUT (adding a package), PATCH (modifying a package), and DELETE (removing a package) require the admin token
	adminMethods := []string{http.MethodPut, http.MethodPatch, http.MethodDelete}
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		authHeaderDigest := sha256.Sum256([]byte(req.Header.Get("Authorization")))
		authHeaderDigestStr := fmt.Sprintf("%x", authHeaderDigest[:])

		if slices.Contains(adminMethods, req.Method) {
			if s.ArmoryServerConfig.AdminAuthorizationTokenDigest != "" && authHeaderDigestStr == s.ArmoryServerConfig.AdminAuthorizationTokenDigest {
				next.ServeHTTP(resp, req)
				return
			} else {
				s.jsonForbidden(resp, errors.New("user is not authenticated"))
				return
			}
		}

		if !s.ArmoryServerConfig.ClientAuthenticationDisabled {
			if authHeaderDigestStr == s.ArmoryServerConfig.ClientAuthorizationTokenDigest {
				next.ServeHTTP(resp, req)
				return
			} else {
				s.jsonForbidden(resp, errors.New("user is not authenticated"))
				return
			}
		} else {
			next.ServeHTTP(resp, req)
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
