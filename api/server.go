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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// ArmoryServer - The armory server object
type ArmoryServer struct {
	HTTPServer         *http.Server
	ArmoryServerConfig *ArmoryServerConfig
	AccessLog          *logrus.Logger
	AppLog             *logrus.Logger
}

// ArmoryServerConfig - Configuration options for the Armory server
type ArmoryServerConfig struct {
	DomainName string `json:"domain_name"`
	ListenHost string `json:"lhost"`
	ListenPort uint16 `json:"lport"`

	RootDir    string `json:"root_dir"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`

	AuthorizationTokenDigest string `json:"authorization_token_digest"`

	WriteTimeout time.Duration `json:"write_timeout"`
	ReadTimeout  time.Duration `json:"read_timeout"`
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
	router.Use(server.defaultHeadersMiddleware)

	// Public Handlers
	router.HandleFunc("/health", server.healthHandler)

	// Armory Handlers
	armoryRouter := router.PathPrefix("/armory").Subrouter()
	armoryRouter.Use(server.loggingMiddleware)
	if server.ArmoryServerConfig.AuthorizationTokenDigest != "" {
		armoryRouter.Use(server.authorizationTokenMiddleware)
	}

	armoryRouter.HandleFunc("/index", server.IndexHandler).Methods(http.MethodGet)
	armoryRouter.HandleFunc("/aliases", server.AliasesHandler).Methods(http.MethodGet)
	armoryRouter.HandleFunc("/extensions", server.ExtensionsHandler).Methods(http.MethodGet)

	server.HTTPServer = &http.Server{
		Handler:      router,
		Addr:         fmt.Sprintf("%s:%d", config.ListenHost, config.ListenPort),
		WriteTimeout: config.WriteTimeout,
		ReadTimeout:  config.ReadTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	return server
}

// --------------
// Handlers
// --------------

// IndexHandler
func (s *ArmoryServer) IndexHandler(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal("{}")
	if err != nil {
		s.jsonError(resp, err)
		return
	}
	resp.WriteHeader(http.StatusOK)
	resp.Write(data)
}

// AliasesHandler
func (s *ArmoryServer) AliasesHandler(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/octet-stream")
	data, err := json.Marshal("{}")
	if err != nil {
		s.jsonError(resp, err)
		return
	}
	resp.WriteHeader(http.StatusOK)
	resp.Write(data)
}

// ExtensionsHandler
func (s *ArmoryServer) ExtensionsHandler(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/octet-stream")
	data, err := json.Marshal("{}")
	if err != nil {
		s.jsonError(resp, err)
		return
	}
	resp.WriteHeader(http.StatusOK)
	resp.Write(data)
}

// --------------
// Middleware
// --------------

func (s *ArmoryServer) authorizationTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		authHeaderDigest := sha256.Sum256([]byte(req.Header.Get("Authorization")))
		if string(authHeaderDigest[:]) == s.ArmoryServerConfig.AuthorizationTokenDigest {
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
	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(http.StatusOK)
	resp.Write([]byte(`{"health": "ok"}`))
}

func (s *ArmoryServer) jsonError(resp http.ResponseWriter, err error) {
	resp.WriteHeader(http.StatusBadRequest)
	resp.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(JSONError{Error: err.Error()})
	s.AppLog.Error(err)
	resp.Write(data)
}

func (s *ArmoryServer) jsonForbidden(resp http.ResponseWriter, err error) {
	resp.WriteHeader(http.StatusForbidden)
	resp.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(JSONError{Error: err.Error()})
	s.AppLog.Error(err)
	resp.Write(data)
}
