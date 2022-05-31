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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"aead.dev/minisign"
	"github.com/AlecAivazis/survey/v2"
	"github.com/sliverarmory/external-armory/api"
	"github.com/spf13/cobra"
)

const (
	armoryRootDirName = "armory-root"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Perform initial setup",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		rootDir, err := cmd.Flags().GetString(rootDirFlagStr)
		if err != nil {
			fmt.Printf("Error parsing flag --%s, %s\n", rootDirFlagStr, err)
			return
		}
		if rootDir == "" {
			cwd, _ := os.Getwd()
			rootDir = filepath.Join(cwd, armoryRootDirName)
		}
		if _, err := os.Stat(rootDir); os.IsNotExist(err) {
			fmt.Printf("Root directory '%s' does not exist!\n", rootDir)
			if userConfirm(fmt.Sprintf("Create root directory '%s' ?", rootDir)) {
				err = os.Mkdir(rootDir, 0755)
				if err != nil {
					fmt.Printf("Error failed to create '%s' %s\n", rootDir, err)
					return
				}
				os.Mkdir(filepath.Join(rootDir, "extensions"), 0755)
				os.Mkdir(filepath.Join(rootDir, "aliases"), 0755)
				ioutil.WriteFile(filepath.Join(rootDir, "bundles.json"), []byte(`{}`), 0644)
			} else {
				return
			}
		}

		fmt.Printf("Generating default configuration: %s\n", filepath.Join(rootDir, "config.json"))
		public, private, err := minisign.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Printf("Failed to generate public/private key(s): %s\n", err)
			return
		}
		password := userPassword()
		encryptedPrivateKey, err := minisign.EncryptKey(password, private)
		if err != nil {
			fmt.Printf("Failed to encrypt private key: %s\n", err)
			return
		}

		token, tokenDigest := randomAuthorizationToken()

		configData, _ := json.MarshalIndent(&api.ArmoryServerConfig{
			ListenHost:               "",
			ListenPort:               8888,
			RootDir:                  rootDir,
			AuthorizationTokenDigest: tokenDigest,
			PublicKey:                public.String(),
			PrivateKey:               string(encryptedPrivateKey),
		}, "", "  ")
		ioutil.WriteFile(filepath.Join(rootDir, "config.json"), configData, 0644)

		fmt.Printf("****************************************************\n")
		fmt.Printf("Authorization token: %s\n", token)
		fmt.Printf("         Public key: %s", public.String())
		fmt.Printf("****************************************************\n")
	},
}

func userPassword() string {
	password := ""
	prompt := &survey.Password{
		Message: "Encrypt private key with password:",
	}
	survey.AskOne(prompt, &password)
	return password
}

func userConfirm(msg string) bool {
	confirmed := false
	prompt := &survey.Confirm{Message: msg}
	survey.AskOne(prompt, &confirmed)
	return confirmed
}
