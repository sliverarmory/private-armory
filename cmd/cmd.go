package cmd

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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/api/storage"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/sliverarmory/external-armory/log"
	"github.com/spf13/cobra"
)

var (
	runningServerConfig              *api.ArmoryServerConfig = nil
	ErrServerNotInitialized                                  = errors.New("server not initialized - run setup first")
	ErrSigningProviderNotInitialized                         = errors.New("signing key provider not initialized - run setup first")
	ErrStorageProviderNotInitialized                         = errors.New("storage provider not initialized - run setup first")
)

const (
	// ANSI Colors
	Normal    = "\033[0m"
	Black     = "\033[30m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Orange    = "\033[33m"
	Blue      = "\033[34m"
	Purple    = "\033[35m"
	Cyan      = "\033[36m"
	Gray      = "\033[37m"
	Bold      = "\033[1m"
	Clearln   = "\r\x1b[2K"
	UpN       = "\033[%dA"
	DownN     = "\033[%dB"
	Underline = "\033[4m"

	// Info - Display colorful information
	Info = Bold + Cyan + "[*] " + Normal
	// Warn - Warn a user
	Warn = Bold + Red + "[!] " + Normal
	// Debug - Display debug information
	Debug = Bold + Purple + "[-] " + Normal
	// Woot - Display success
	Woot = Bold + Green + "[$] " + Normal
	// Success - Display success
	Success = Bold + Green + "[+] " + Normal
)

func init() {
	rootCmd.Flags().StringP(consts.ConfigFlagStr, "c", "", "Config file path")
	rootCmd.MarkFlagFilename(consts.ConfigFileName, "json")

	rootCmd.Flags().BoolP(consts.UpdateConfigFlagStr, "u", false, "Update server config file based on command line arguments and environment variables")
	rootCmd.Flags().BoolP(consts.DisableAuthFlagStr, "A", false, "Disable authentication token checks")
	rootCmd.Flags().StringP(consts.LhostFlagStr, "l", "", "Listen host")
	rootCmd.Flags().Uint16P(consts.LportFlagStr, "p", 8888, "Listen port")
	rootCmd.Flags().StringP(consts.ReadTimeoutFlagStr, "R", "1m", "HTTP read timeout expressed as a duration")
	rootCmd.Flags().StringP(consts.WriteTimeoutFlagStr, "W", "1m", "HTTP write timeout expressed as a duration")
	rootCmd.Flags().BoolP(consts.RefreshFlagStr, "r", false, "Force refresh of armory index (may require password input)")
	rootCmd.Flags().StringP(consts.AWSSigningKeySecretNameFlagStr, "a", "", "Name for the signing key if using AWS Secrets Manager")
	rootCmd.Flags().StringP(consts.AWSRegionFlagStr, "g", "us-west-2", "AWS region if using Secrets Manager")
	rootCmd.Flags().StringP(consts.VaultURLFlagStr, "U", "", "Vault location as a URL")
	rootCmd.Flags().StringP(consts.VaultAppRolePathFlagStr, "L", "", "The approle path for Vault")
	rootCmd.Flags().StringP(consts.VaultRoleIDFlagStr, "I", "", "The GUID for the approle role ID in Vault")
	rootCmd.Flags().StringP(consts.VaultSecretIDFlagStr, "S", "", "The GUID for the approle secret ID in Vault")
	rootCmd.Flags().StringP(consts.VaultKeyPathFlagStr, "P", "", "The path to the signing key in Vault, including the field")
	rootCmd.Flags().StringP(consts.DomainFlagStr, "m", "", "The domain name or IP address that clients will use to connect to the armory")
	rootCmd.Flags().BoolP(consts.EnableTLSFlagStr, "t", false, "Enable TLS for the armory (certificates must be placed in <armory-root>/certificates, see documentation)")
	rootCmd.Flags().StringP(consts.RootDirFlagStr, "d", "", "Root armory directory (must be writable)")
	rootCmd.MarkFlagDirname(consts.RootDirFlagStr)
	rootCmd.Flags().StringP(consts.PublicKeyFlagStr, "K", "", "Public key for an external signing provider")

	genSignatureCmd.Flags().StringP(consts.FileFlagStr, "f", "", "Path to output key")
	genSignatureCmd.Flags().BoolP(consts.PasswordFlagStr, "p", false, "Prompt for password for generated key")

	signCmd.PersistentFlags().StringP(consts.KeyFlagStr, "k", "", "Path to the private key")
	signCmd.PersistentFlags().BoolP(consts.PasswordFlagStr, "p", false, "Prompt for password for the private key")
	signCmd.PersistentFlags().StringP(consts.PasswordFileFlagStr, "a", "", "Path to a file containing the password")

	signPackageCmd.Flags().StringP(consts.ConfigFlagStr, "c", "", "Path to a configuration file for the armory (required)")
	signPackageCmd.Flags().StringP(consts.FileFlagStr, "f", "", "Path to the package to sign (required)")
	signPackageCmd.MarkFlagFilename(consts.ConfigFlagStr, "json")
	signPackageCmd.MarkFlagRequired(consts.ConfigFlagStr)
	signPackageCmd.MarkFlagFilename(consts.FileFlagStr, "tar.gz")
	signPackageCmd.MarkFlagRequired(consts.FileFlagStr)

	signIndexCmd.Flags().StringP(consts.ConfigFlagStr, "c", "", "Path to a configuration file for the armory (required)")
	signIndexCmd.MarkFlagFilename(consts.ConfigFileName, "json")
	signIndexCmd.MarkFlagRequired(consts.ConfigFlagStr)

	signCmd.AddCommand(signPackageCmd)
	signCmd.AddCommand(signIndexCmd)

	refreshCmd.Flags().StringP(consts.ConfigFlagStr, "c", "", "Config file path")
	refreshCmd.MarkFlagFilename(consts.ConfigFlagStr, "json")
	rootCmd.AddCommand(refreshCmd)
	rootCmd.AddCommand(genSignatureCmd)
	rootCmd.AddCommand(signCmd)
}

var rootCmd = &cobra.Command{
	Use:   "armory-server",
	Short: "Sliver armory server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		err := getServerConfig(cmd)
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		storagePaths, err := runningServerConfig.StorageProvider.Paths()
		if err != nil {
			// Then the storage provider was not initialized, and we need to bail
			// We *should* never get here since errors during initialization would
			// be caught above.
			panic("The storage provider did not initialize properly")
		}
		appLogFile, err := runningServerConfig.StorageProvider.GetLogger(consts.AppLogName)
		if err != nil {
			panic(fmt.Sprintf("Failed to open app log file: %v", err))
		}
		accessLogFile, err := runningServerConfig.StorageProvider.GetLogger(consts.AccessLogName)
		if err != nil {
			panic(fmt.Sprintf("Failed to open access log file: %v", err))
		}
		appLog := log.StartLogger(appLogFile)
		server := api.New(runningServerConfig,
			appLog,
			log.StartLogger(accessLogFile),
		)
		appLog.Infof("Starting with root dir: %s", runningServerConfig.StorageProvider.BasePath())

		forceRefresh, err := cmd.Flags().GetBool(consts.RefreshFlagStr)
		if err != nil {
			fmt.Printf("Error parsing flag --%s, %s\n", consts.RefreshFlagStr, err)
			return
		}

		if _, err := runningServerConfig.StorageProvider.ReadIndex(); errors.Is(err, storage.ErrDoesNotExist) || forceRefresh {
			if !forceRefresh {
				appLog.Warnf("Armory index not found %s, will attempt to refresh ...", storagePaths.Index)
			} else {
				appLog.Infof("Forcing refresh of armory index ...")
			}
			errors := refreshArmoryIndex()
			if len(errors) > 0 {
				for _, err := range errors {
					appLog.Errorln(err)
				}
				os.Exit(2)
			}
		}

		// Set up TLS
		var tlsCertPair tls.Certificate
		tlsSetup := false

		if server.ArmoryServerConfig.TLSEnabled {
			certData, err := runningServerConfig.StorageProvider.ReadTLSCertificateCrt()
			if err != nil {
				appLog.Warnf("Error getting TLS certificate from storage provider: %s", err)
			}
			keyData, err := runningServerConfig.StorageProvider.ReadTLSCertificateKey()
			if err != nil {
				appLog.Warnf("Error getting TLS key from storage provider: %s", err)
			}
			tlsCertPair, err = tls.X509KeyPair(certData, keyData)
			if err != nil {
				appLog.Warnf("Error validating TLS key pair: %s", err)
			}
			tlsSetup = true
		}

		// Watcher
		// Receive events from the storage provider
		eventChannel, errorChannel, err := runningServerConfig.StorageProvider.AutoRefreshChannels()
		if err != nil {
			appLog.Warnf("Package watcher was not initialized. The index will have to be refreshed manually. Error: %s", err)
		} else if eventChannel == nil || errorChannel == nil {
			appLog.Warnln("Storage provider does not support auto package refreshing. The index will have to be refreshed manually.")
		} else {
			appLog.Infoln("Package watcher initialized")
			go func() {
				for {
					select {
					case event, ok := <-eventChannel:
						if !ok {
							return
						}
						appLog.Infof("Change detected: %s, refreshing index...", event)
						errors := refreshArmoryIndex()
						for _, err := range errors {
							appLog.Errorln(err)
						}
					case err, ok := <-errorChannel:
						if !ok {
							return
						}
						appLog.Errorf("Watcher received an error, shutting down package watcher: %s", err)
						return
					}
				}
			}()
		}

		// Refresh the index so that we have the most up to date index before the server starts
		errors := refreshArmoryIndex()
		for _, err := range errors {
			appLog.Errorln(err)
		}

		go func() {
			var err error
			if tlsSetup {
				appLog.Infof("TLS is ENABLED")
				server.HTTPServer.TLSConfig = &tls.Config{
					Certificates: []tls.Certificate{tlsCertPair},
					MinVersion:   tls.VersionTLS13,
				}
				err = server.HTTPServer.ListenAndServeTLS("", "")
			} else {
				appLog.Infof("TLS is DISABLED")
				err = server.HTTPServer.ListenAndServe()
			}
			if err != nil {
				appLog.Errorf("Listener error: %s", err)
				os.Exit(1)
			}
		}()

		// Wait for signal to stop
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.HTTPServer.Shutdown(ctx)
		os.Exit(0)
	},
}

// Execute - Execute the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
