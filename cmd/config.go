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
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/sliverarmory/external-armory/api"
	"github.com/spf13/cobra"
)

func getServerConfig(cmd *cobra.Command) *api.ArmoryServerConfig {
	serverConfig := &api.ArmoryServerConfig{}
	configPath, err := cmd.Flags().GetString(configFlagStr)
	if err != nil {
		fmt.Printf("Error parsing flag --%s, %s\n", configFlagStr, err)
		return nil
	}
	if configPath != "" {
		configData, err := ioutil.ReadFile(configPath)
		if err != nil {
			fmt.Printf("Error reading config file %s, %s\n", configPath, err)
			return nil
		}
		err = json.Unmarshal(configData, serverConfig)
		if err != nil {
			fmt.Printf("Error parsing config file %s, %s\n", configPath, err)
			return nil
		}
	}

	// CLI flags override config file

	disableAuth, err := cmd.Flags().GetBool(disableAuthFlagStr)
	if err != nil {
		fmt.Printf("Error parsing flag --%s, %s\n", disableAuthFlagStr, err)
		return nil
	}
	if !disableAuth && serverConfig.AuthorizationTokenDigest == "" {
		token, tokenDigest := randomAuthorizationToken()
		fmt.Printf("[*] Authorization token: %s\n", token)
		serverConfig.AuthorizationTokenDigest = tokenDigest
	}

	if cmd.Flags().Changed(lhostFlagStr) {
		serverConfig.ListenHost, err = cmd.Flags().GetString(lhostFlagStr)
		if err != nil {
			fmt.Printf("Error parsing flag --%s, %s\n", lhostFlagStr, err)
			return nil
		}
	} else {
		serverConfig.ListenHost = ""
	}

	if cmd.Flags().Changed(lportFlagStr) {
		serverConfig.ListenPort, err = cmd.Flags().GetUint16(lportFlagStr)
		if err != nil {
			fmt.Printf("Error parsing flag --%s, %s\n", lportFlagStr, err)
			return nil
		}
	} else {
		serverConfig.ListenPort = 8888
	}

	return serverConfig
}

func randomAuthorizationToken() (string, string) {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	hexToken := fmt.Sprintf("%x", buf)
	digest := sha256.Sum256([]byte(hexToken))
	return hexToken, fmt.Sprintf("%x", digest)
}
