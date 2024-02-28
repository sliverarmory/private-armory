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
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/sliverarmory/external-armory/log"
	"github.com/spf13/cobra"
)

var runningServerConfig *api.ArmoryServerConfig = nil

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
	rootCmd.PersistentFlags().StringP(consts.ConfigFlagStr, "c", "", "Config file path")

	rootCmd.Flags().BoolP(consts.DisableAuthFlagStr, "A", false, "Disable authentication token checks")
	rootCmd.Flags().StringP(consts.LhostFlagStr, "l", "", "Listen host")
	rootCmd.Flags().Uint16P(consts.LportFlagStr, "p", 8888, "Listen port")
	rootCmd.Flags().StringP(consts.ReadTimeoutFlagStr, "R", "1m", "HTTP read timeout expressed as a duration")
	rootCmd.Flags().StringP(consts.WriteTimeoutFlagStr, "W", "1m", "HTTP write timeout expressed as a duration")
	rootCmd.Flags().BoolP(consts.RefreshFlagStr, "r", false, "Force refresh of armory index (may require password input)")
	rootCmd.Flags().StringP(consts.AWSSigningKeySecretNameFlagStr, "a", "", "Name for the signing key if using AWS Secrets Manager")
	rootCmd.Flags().StringP(consts.AWSRegionFlagStr, "g", "us-west-2", "AWS region if using Secrets Manager")
	rootCmd.Flags().StringP(consts.VaultURLFlagStr, "u", "", "Vault location as a URL")
	rootCmd.Flags().StringP(consts.VaultAppRolePathFlagStr, "L", "", "The approle path for Vault")
	rootCmd.Flags().StringP(consts.VaultRoleIDFlagStr, "i", "", "The GUID for the approle role ID in Vault")
	rootCmd.Flags().StringP(consts.VaultSecretIDFlagStr, "s", "", "The GUID for the approle secret ID in Vault")
	rootCmd.Flags().StringP(consts.VaultKeyPathFlagStr, "P", "", "The path to the signing key in Vault, including the field")
	rootCmd.Flags().StringP(consts.DomainFlagStr, "m", "", "The domain name or IP address that clients will use to connect to the armory")
	rootCmd.Flags().BoolP(consts.EnableTLSFlagStr, "t", false, "Enable TLS for the armory (certificates must be placed in <armory-root>/certificates, see documentation)")
	rootCmd.Flags().StringP(consts.RootDirFlagStr, "d", "", "Root armory directory (must be writable)")

	genSignatureCmd.Flags().StringP("file", "f", "", "Path to output key")

	rootCmd.AddCommand(refreshCmd)
	rootCmd.AddCommand(genSignatureCmd)
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
		appLog := log.GetAppLogger(runningServerConfig.RootDir)
		server := api.New(runningServerConfig,
			appLog,
			log.GetAccessLogger(runningServerConfig.RootDir),
		)
		appLog.Infof("Starting with root dir: %s", runningServerConfig.RootDir)

		forceRefresh, err := cmd.Flags().GetBool(consts.RefreshFlagStr)
		if err != nil {
			fmt.Printf("Error parsing flag --%s, %s\n", consts.RefreshFlagStr, err)
			return
		}

		if _, err := os.Stat(filepath.Join(runningServerConfig.RootDir, consts.ArmoryIndexFileName)); os.IsNotExist(err) || forceRefresh {
			if !forceRefresh {
				appLog.Warnf("Armory index not found %s, will attempt to refresh ...",
					filepath.Join(runningServerConfig.RootDir, consts.ArmoryIndexFileName),
				)
			} else {
				appLog.Infof("Forcing refresh of armory index ...")
			}
			success := refreshArmoryIndex(appLog)
			if !success {
				os.Exit(2)
			}
		}

		// Watcher
		packageWatcher, err := fsnotify.NewWatcher()
		enableWatcher := true
		if err != nil {
			appLog.Errorf("Could not initialize package watcher. Packages will have to be refreshed manually: %s", err)
			enableWatcher = false
		}

		if enableWatcher {
			defer packageWatcher.Close()
			go func() {
				for {
					select {
					case event, ok := <-packageWatcher.Events:
						if !ok {
							return
						}
						if event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Write) {
							// a file has been added or removed, so force a refresh
							appLog.Infof("Change detected in %s, refreshing index...", filepath.Dir(event.Name))
							refreshArmoryIndex(appLog)
						}
					case err, ok := <-packageWatcher.Errors:
						if !ok {
							return
						}
						appLog.Errorf("Watcher received an error: %s", err)
					}
				}
			}()

			err = packageWatcher.Add(filepath.Join(server.ArmoryServerConfig.RootDir, consts.AliasesDirName))
			if err != nil {
				appLog.Errorf("Could not watch alias dir, disabling watcher: %s", err)
				packageWatcher.Close()
			} else {
				err = packageWatcher.Add(filepath.Join(server.ArmoryServerConfig.RootDir, consts.ExtensionsDirName))
				if err != nil {
					appLog.Errorf("Could not watch extensions dir, disabling watcher: %s", err)
					packageWatcher.Close()
				} else {
					err = packageWatcher.Add(filepath.Join(server.ArmoryServerConfig.RootDir, consts.BundlesFileName))
					if err != nil {
						appLog.Errorf("Could not watch bundle file, disabling watcher: %s", err)
						packageWatcher.Close()
					}
				}
			}
		}

		go func() {
			var err error
			if server.ArmoryServerConfig.TLSEnabled {
				certPath := filepath.Join(server.ArmoryServerConfig.RootDir, consts.TLSCertPathFromRoot)
				keyPath := filepath.Join(server.ArmoryServerConfig.RootDir, consts.TLSKeyPathFromRoot)
				appLog.Infof("TLS is ENABLED")
				appLog.Debugf("TLS certificate file: %s", certPath)
				if _, err := os.Stat(certPath); os.IsNotExist(err) {
					appLog.Warnf("TLS certificate file path does not exist '%s'", certPath)
				}
				appLog.Debugf("TLS key file: %s", keyPath)
				if _, err := os.Stat(keyPath); os.IsNotExist(err) {
					appLog.Warnf("TLS key file path does not exist '%s'", keyPath)
				}
				err = server.HTTPServer.ListenAndServeTLS(certPath, keyPath)
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
