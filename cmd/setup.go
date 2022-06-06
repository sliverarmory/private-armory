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
	"path"
	"path/filepath"
	"time"

	"aead.dev/minisign"
	"github.com/AlecAivazis/survey/v2"
	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/spf13/cobra"
)

const (
	privateKeyFileName = "private.key"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Perform initial setup",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		rootDir, err := getRootDir(cmd)
		if err != nil {
			fmt.Printf(Warn+"%s\n", err)
			return
		}
		if _, err := os.Stat(rootDir); os.IsNotExist(err) {
			fmt.Printf(Info+"Root directory '%s' does not exist!\n", rootDir)
			if userConfirm(fmt.Sprintf("Create root directory '%s' ?", rootDir)) {
				err = os.Mkdir(rootDir, 0755)
				if err != nil {
					fmt.Printf(Warn+"Error failed to create '%s' %s\n", rootDir, err)
					return
				}
				os.Mkdir(filepath.Join(rootDir, consts.ExtensionsDirName), 0755)
				os.Mkdir(filepath.Join(rootDir, consts.AliasesDirName), 0755)
				os.Mkdir(filepath.Join(rootDir, consts.SignaturesDirName), 0755)
				ioutil.WriteFile(filepath.Join(rootDir, consts.BundlesFileName), []byte(`[]`), 0644)
			} else {
				return
			}
		}

		domain := ""
		survey.AskOne(&survey.Input{Message: "Domain name (or blank):"}, &domain)

		enableTLS := userConfirm("Enable TLS?")

		fmt.Printf(Info+"Generating default configuration: %s\n", filepath.Join(rootDir, consts.ConfigFileName))
		public, private, err := minisign.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Printf(Warn+"Failed to generate public/private key(s): %s\n", err)
			return
		}
		password := userPassword()
		encryptedPrivateKey, err := minisign.EncryptKey(password, private)
		if err != nil {
			fmt.Printf("Failed to encrypt private key: %s\n", err)
			return
		}
		ioutil.WriteFile(filepath.Join(rootDir, privateKeyFileName), encryptedPrivateKey, 0644)
		token, tokenDigest := randomAuthorizationToken()
		serverConfig := &api.ArmoryServerConfig{
			DomainName:               domain,
			ListenHost:               "",
			ListenPort:               8888,
			RootDir:                  rootDir,
			AuthorizationTokenDigest: tokenDigest,
			PublicKey:                public.String(),
			TLSEnabled:               enableTLS,
			WriteTimeout:             time.Duration(5 * time.Minute),
			ReadTimeout:              time.Duration(5 * time.Minute),
		}
		serverConfigData, _ := json.MarshalIndent(serverConfig, "", "  ")
		ioutil.WriteFile(filepath.Join(rootDir, consts.ConfigFileName), serverConfigData, 0644)

		fmt.Println()
		userConfig, _ := json.MarshalIndent(&ArmoryClientConfig{
			PublicKey:     public.String(),
			RepoURL:       serverConfig.RepoURL() + "/" + path.Join("armory", "index"),
			Authorization: token,
		}, "", "    ")
		fmt.Printf(Bold + "*** THIS WILL ONLY BE SHOWN ONCE ***\n")
		fmt.Printf(Bold+">>> User Config:%s\n%s\n", Normal, userConfig)
	},
}

func userPassword() string {
	if os.Getenv("ARMORY_BLANK_PASSWORD") == "1" {
		return ""
	}
	password := ""
	prompt := &survey.Password{Message: "Private key password:"}
	survey.AskOne(prompt, &password)
	return password
}

func userConfirm(msg string) bool {
	confirmed := false
	prompt := &survey.Confirm{Message: msg}
	survey.AskOne(prompt, &confirmed)
	return confirmed
}

func getRootDir(cmd *cobra.Command) (string, error) {
	rootDir, err := cmd.Flags().GetString(rootDirFlagStr)
	if err != nil {
		return "", fmt.Errorf("Error parsing flag --%s, %s", rootDirFlagStr, err)
	}
	if rootDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		rootDir = filepath.Join(cwd, consts.ArmoryRootDirName)
	}
	return rootDir, nil
}
