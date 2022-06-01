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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/sliverarmory/external-armory/api"
	"github.com/spf13/cobra"
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
		generateArmoryIndex(serverConfig.RootDir)
	},
}

// GenerateArmoryIndex - Generate the armory index
func generateArmoryIndex(rootDir string) error {
	aliases, err := getAliases(rootDir)
	if err != nil {
		return err
	}
	extensions, err := getExtensions(rootDir)
	if err != nil {
		return err
	}
	bundles, err := getBundles(rootDir)
	if err != nil {
		return err
	}

	armoryIndex := &api.ArmoryIndex{
		Aliases:    aliases,
		Extensions: extensions,
		Bundles:    bundles,
	}

	_, err = json.MarshalIndent(armoryIndex, "", "  ")
	if err != nil {
		return err
	}

	return nil
}

func getAliases(rootDir string) ([]*api.ArmoryEntry, error) {
	aliasesPath := filepath.Join(rootDir, aliasesDirName)
	if _, err := os.Stat(aliasesPath); os.IsNotExist(err) {
		return nil, err
	}
	fi, err := ioutil.ReadDir(aliasesPath)
	if err != nil {
		return nil, err
	}

	entries := []*api.ArmoryEntry{}
	for _, entry := range fi {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
	}

	return entries, nil
}

func getExtensions(rootDir string) ([]*api.ArmoryEntry, error) {
	extensionsPath := filepath.Join(rootDir, extensionsDirName)
	if _, err := os.Stat(extensionsPath); os.IsNotExist(err) {
		return nil, err
	}
	fi, err := ioutil.ReadDir(extensionsPath)
	if err != nil {
		return nil, err
	}

	entries := []*api.ArmoryEntry{}
	for _, entry := range fi {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
	}

	return entries, nil
}

func getBundles(rootDir string) ([]*api.ArmoryBundle, error) {

	return nil, nil
}
