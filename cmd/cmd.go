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

func init() {
	rootCmd.PersistentFlags().StringP(configFlagStr, "c", "", "Config file path")

	rootCmd.Flags().BoolP(disableAuthFlagStr, "A", false, "Disable authentication token checks")
	rootCmd.Flags().StringP(lhostFlagStr, "l", "", "Listen host")
	rootCmd.Flags().Uint16P(lportFlagStr, "p", 8888, "Listen port")
	rootCmd.Flags().StringP(readTimeoutFlagStr, "r", "1m", "HTTP read timeout")
	rootCmd.Flags().StringP(writeTimeoutFlagStr, "w", "1m", "HTTP write timeout")

	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(refreshCmd)
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(rmCmd)
	rootCmd.AddCommand(lsCmd)
}

var rootCmd = &cobra.Command{
	Use:   "armory-server",
	Short: "Sliver armory server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		startServer(cmd, args)
	},
}

func startServer(cmd *cobra.Command, args []string) {
	serverConfig := getServerConfig(cmd)
	if serverConfig == nil {
		return
	}

	// Start server
	server := api.New(serverConfig,
		log.GetAppLogger(serverConfig.RootDir),
		log.GetAccessLogger(serverConfig.RootDir),
	)
	go func() {
		err := server.HTTPServer.ListenAndServe()
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
}

// Execute - Execute the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
