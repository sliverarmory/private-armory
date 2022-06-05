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
	"os"
	"os/signal"
	"time"

	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/log"
	"github.com/spf13/cobra"
)

const (
	lhostFlagStr        = "lhost"
	lportFlagStr        = "lport"
	configFlagStr       = "config"
	writeTimeoutFlagStr = "write-timeout"
	readTimeoutFlagStr  = "read-timeout"
	disableAuthFlagStr  = "disable-authentication"

	rootDirFlagStr = "root-dir"
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
	// Success - Diplay success
	Success = Bold + Green + "[+] " + Normal
)

func init() {
	rootCmd.PersistentFlags().StringP(configFlagStr, "c", "", "Config file path")

	rootCmd.Flags().BoolP(disableAuthFlagStr, "A", false, "Disable authentication token checks")
	rootCmd.Flags().StringP(lhostFlagStr, "l", "", "Listen host")
	rootCmd.Flags().Uint16P(lportFlagStr, "p", 8888, "Listen port")
	rootCmd.Flags().StringP(readTimeoutFlagStr, "r", "1m", "HTTP read timeout")
	rootCmd.Flags().StringP(writeTimeoutFlagStr, "w", "1m", "HTTP write timeout")

	rootCmd.AddCommand(setupCmd)
	setupCmd.Flags().StringP("root-dir", "R", "", "Root armory directory (must be writable)")

	rootCmd.AddCommand(refreshCmd)
}

var rootCmd = &cobra.Command{
	Use:   "armory-server",
	Short: "Sliver armory server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		serverConfig := getServerConfig(cmd)
		if serverConfig == nil {
			return
		}
		appLog := log.GetAppLogger(serverConfig.RootDir)
		server := api.New(serverConfig,
			appLog,
			log.GetAccessLogger(serverConfig.RootDir),
		)
		appLog.Infof("Starting with root dir: %s", serverConfig.RootDir)
		go func() {
			var err error
			if server.ArmoryServerConfig.TLSEnabled {
				appLog.Infof("TLS is ENABLED")
				appLog.Debugf("TLS certificate file: %s", server.ArmoryServerConfig.TLSCertificate)
				appLog.Debugf("TLS key file: %s", server.ArmoryServerConfig.TLSKey)
				err = server.HTTPServer.ListenAndServeTLS(
					server.ArmoryServerConfig.TLSCertificate,
					server.ArmoryServerConfig.TLSKey,
				)
			} else {
				appLog.Infof("TLS is DISABLED")
				err = server.HTTPServer.ListenAndServe()
			}
			if err != nil {
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
