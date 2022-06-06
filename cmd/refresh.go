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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"
	"github.com/sirupsen/logrus"
	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/sliverarmory/external-armory/log"
	"github.com/spf13/cobra"
)

const (
	armoryIndexFileName    = "armory-index.json"
	armoryIndexSigFileName = "armory-index.minisig"
)

var refreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Refresh the armory index",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		serverConfig := getServerConfig(cmd)
		if serverConfig == nil {
			return
		}
		appLog := log.GetAppLogger(serverConfig.RootDir)
		fmt.Printf(Info + "Refreshing armory index ...\n")
		success, data := refreshArmoryIndex(serverConfig, appLog)
		if !success {
			fmt.Printf(Warn + "Failed to refresh armory index, check logs")
			return
		}
		fmt.Printf(Info + "Signing armory index ...\n")
		signArmoryIndex(data, serverConfig, appLog)
		fmt.Printf(Success + "Successfully refreshed armory index.\n")
	},
}

func signArmoryIndex(data []byte, serverConfig *api.ArmoryServerConfig, appLog *logrus.Logger) {
	password := userPassword()
	privateKey, err := minisign.PrivateKeyFromFile(password, filepath.Join(serverConfig.RootDir, privateKeyFileName))
	if err != nil {
		appLog.Errorf("Failed to load private key: %s", err)
		return
	}
	sig := minisign.Sign(privateKey, data)
	err = ioutil.WriteFile(filepath.Join(serverConfig.RootDir, armoryIndexSigFileName), sig, 0644)
	if err != nil {
		appLog.Errorf("Failed to write armory index signature: %s", err)
		return
	}
}

func refreshArmoryIndex(serverConfig *api.ArmoryServerConfig, appLog *logrus.Logger) (bool, []byte) {
	index, err := generateArmoryIndex(serverConfig.RootDir)
	if err != nil {
		appLog.Errorf("Failed to generate armory index: %s", err)
		return false, nil
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		appLog.Errorf("Failed to marshal armory index: %s", err)
		return false, nil
	}
	err = ioutil.WriteFile(filepath.Join(serverConfig.RootDir, armoryIndexFileName), data, 0644)
	if err != nil {
		appLog.Errorf("Failed to write armory index: %s", err)
		return false, nil
	}
	return true, data
}

// GenerateArmoryIndex - Generate the armory index
func generateArmoryIndex(rootDir string) (*api.ArmoryIndex, error) {
	aliases, err := getAliases(rootDir)
	if err != nil {
		return nil, err
	}
	extensions, err := getExtensions(rootDir)
	if err != nil {
		return nil, err
	}
	bundles, err := getBundles(rootDir)
	if err != nil {
		return nil, err
	}
	return &api.ArmoryIndex{
		Aliases:    aliases,
		Extensions: extensions,
		Bundles:    bundles,
	}, nil
}

func getAliases(rootDir string) ([]*api.ArmoryEntry, error) {
	appLog := log.GetAppLogger(rootDir)
	aliasesPath := filepath.Join(rootDir, consts.AliasesDirName)
	appLog.Infof("Looking for aliases in %s", aliasesPath)
	if _, err := os.Stat(aliasesPath); os.IsNotExist(err) {
		appLog.Errorf("Failed to find aliases: %s", err)
		return nil, err
	}
	fi, err := ioutil.ReadDir(aliasesPath)
	if err != nil {
		appLog.Errorf("Failed to find aliases: %s", err)
		return nil, err
	}

	entries := []*api.ArmoryEntry{}
	for _, entry := range fi {
		if entry.IsDir() {
			appLog.Debugf("%v is a directory (skip)", entry)
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".tar.gz") {
			appLog.Debugf("%v not a .tar.gz file (skip)", entry)
			continue
		}
	}

	return entries, nil
}

func getExtensions(rootDir string) ([]*api.ArmoryEntry, error) {
	appLog := log.GetAppLogger(rootDir)
	extensionsPath := filepath.Join(rootDir, consts.ExtensionsDirName)
	appLog.Infof("Looking for extensions in %s", extensionsPath)
	if _, err := os.Stat(extensionsPath); os.IsNotExist(err) {
		appLog.Errorf("Failed to find extensions: %s", err)
		return nil, err
	}
	fi, err := ioutil.ReadDir(extensionsPath)
	if err != nil {
		appLog.Errorf("Failed to find extensions: %s", err)
		return nil, err
	}

	entries := []*api.ArmoryEntry{}
	for _, entry := range fi {
		if entry.IsDir() {
			appLog.Debugf("%v is a directory (skip)", entry)
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".tar.gz") {
			appLog.Debugf("%v not a .tar.gz file (skip)", entry)
			continue
		}
	}

	return entries, nil
}

func getBundles(rootDir string) ([]*api.ArmoryBundle, error) {
	bundleData, err := ioutil.ReadFile(filepath.Join(rootDir, consts.BundlesFileName))
	if err != nil {
		return nil, err
	}
	bundles := []*api.ArmoryBundle{}
	err = json.Unmarshal(bundleData, &bundles)
	return bundles, err
}
