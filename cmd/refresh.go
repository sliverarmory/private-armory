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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"aead.dev/minisign"

	"github.com/sirupsen/logrus"
	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/sliverarmory/external-armory/log"
	"github.com/sliverarmory/external-armory/util"
	"github.com/spf13/cobra"
)

type ExtensionManifest struct {
	Name            string               `json:"name"`
	CommandName     string               `json:"command_name"`
	Version         string               `json:"version"`
	ExtensionAuthor string               `json:"extension_author"`
	OriginalAuthor  string               `json:"original_author"`
	RepoURL         string               `json:"repo_url"`
	Help            string               `json:"help"`
	LongHelp        string               `json:"long_help"`
	Files           []*extensionFile     `json:"files"`
	Arguments       []*extensionArgument `json:"arguments"`
	Entrypoint      string               `json:"entrypoint"`
	DependsOn       string               `json:"depends_on"`
	Init            string               `json:"init"`
}

type extensionFile struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Path string `json:"path"`
}

type extensionArgument struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Desc     string `json:"desc"`
	Optional bool   `json:"optional"`
}

// AliasFile - An OS/Arch specific file
type AliasFile struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Path string `json:"path"`
}

// AliasManifest - The manifest for an alias, contains metadata
type AliasManifest struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	CommandName    string `json:"command_name"`
	OriginalAuthor string `json:"original_author"`
	RepoURL        string `json:"repo_url"`
	Help           string `json:"help"`
	LongHelp       string `json:"long_help"`

	Entrypoint   string       `json:"entrypoint"`
	AllowArgs    bool         `json:"allow_args"`
	DefaultArgs  string       `json:"default_args"`
	Files        []*AliasFile `json:"files"`
	IsReflective bool         `json:"is_reflective"`
	IsAssembly   bool         `json:"is_assembly"`
}

var refreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Refresh the armory index",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		err := getServerConfig(cmd)
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		appLog := log.GetAppLogger(runningServerConfig.RootDir)
		fmt.Printf(Info + "Refreshing armory index ...\n")
		success := refreshArmoryIndex(appLog)
		if !success {
			fmt.Printf(Warn + "Failed to refresh armory index, check logs")
			return
		}
		fmt.Printf(Success + "Successfully refreshed armory index.\n")
	},
}

func signArmoryIndex(privateKey minisign.PrivateKey, data []byte, appLog *logrus.Logger) {
	sig := minisign.Sign(privateKey, data)
	err := os.WriteFile(filepath.Join(runningServerConfig.RootDir, consts.ArmoryIndexSigFileName), sig, 0644)
	if err != nil {
		appLog.Errorf("Failed to write armory index signature: %s", err)
		return
	}
}

func refreshArmoryIndex(appLog *logrus.Logger) bool {
	if runningServerConfig.SigningKey == nil {
		appLog.Errorf("Cannot refresh armory index since no package signing key has been loaded")
		return false
	}

	index, err := generateArmoryIndex(runningServerConfig.RootDir, *runningServerConfig.SigningKey)
	if err != nil {
		appLog.Errorf("Failed to generate armory index: %s", err)
		return false
	}
	for _, entry := range index.Aliases {
		entry.PublicKey = runningServerConfig.PublicKey
		entry.RepoURL, err = url.JoinPath(runningServerConfig.RepoURL(), "armory", consts.AliasesDirName, path.Base(entry.CommandName))
		if err != nil {
			appLog.Errorf("Failed to create URL for alias %s: %s\n", entry.CommandName, err)
			continue
		}
	}
	for _, entry := range index.Extensions {
		entry.PublicKey = runningServerConfig.PublicKey
		entry.RepoURL, err = url.JoinPath(runningServerConfig.RepoURL(), "armory", consts.ExtensionsDirName, path.Base(entry.CommandName))
		if err != nil {
			appLog.Errorf("Failed to create URL for extension %s: %s\n", entry.CommandName, err)
			continue
		}
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		appLog.Errorf("Failed to marshal armory index: %s", err)
		return false
	}
	err = os.WriteFile(filepath.Join(runningServerConfig.RootDir, consts.ArmoryIndexFileName), data, 0644)
	if err != nil {
		appLog.Errorf("Failed to write armory index: %s", err)
		return false
	}
	signArmoryIndex(*runningServerConfig.SigningKey, data, appLog)
	return true
}

func signFile(rootDir string, privateKey minisign.PrivateKey, manifest []byte, fileToSign string) error {
	sigPath := filepath.Join(rootDir, consts.SignaturesDirName, filepath.Base(strings.TrimSuffix(fileToSign, ".tar.gz")))
	data, err := os.ReadFile(fileToSign)
	if err != nil {
		return err
	}
	sigData := minisign.SignWithComments(privateKey, data, base64.StdEncoding.EncodeToString(manifest), "")
	err = os.WriteFile(sigPath, sigData, 0o644)
	return err
}

// GenerateArmoryIndex - Generate the armory index
func generateArmoryIndex(rootDir string, privateKey minisign.PrivateKey) (*api.ArmoryIndex, error) {
	aliases, aliasManifests, err := getAliases(rootDir)
	if err != nil {
		return nil, err
	}
	for commandName, data := range aliasManifests {
		fileToSign := filepath.Join(rootDir, consts.AliasesDirName, fmt.Sprintf("%s.tar.gz", commandName))
		err = signFile(rootDir, privateKey, data, fileToSign)
		if err != nil {
			return nil, err
		}
	}

	extensions, extensionManifests, err := getExtensions(rootDir)
	if err != nil {
		return nil, err
	}
	for commandName, data := range extensionManifests {
		fileToSign := filepath.Join(rootDir, consts.ExtensionsDirName, fmt.Sprintf("%s.tar.gz", commandName))
		err = signFile(rootDir, privateKey, data, fileToSign)
		if err != nil {
			return nil, err
		}
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

func getAliases(rootDir string) ([]*api.ArmoryEntry, map[string][]byte, error) {
	appLog := log.GetAppLogger(rootDir)
	aliasesPath := filepath.Join(rootDir, consts.AliasesDirName)
	appLog.Infof("Looking for aliases in %s", aliasesPath)
	if _, err := os.Stat(aliasesPath); os.IsNotExist(err) {
		appLog.Errorf("Failed to find aliases: %s", err)
		return nil, nil, err
	}
	fi, err := os.ReadDir(aliasesPath)
	if err != nil {
		appLog.Errorf("Failed to find aliases: %s", err)
		return nil, nil, err
	}

	entries := []*api.ArmoryEntry{}
	manifests := map[string][]byte{}

	for _, entry := range fi {
		archivePath := filepath.Join(aliasesPath, entry.Name())
		if entry.IsDir() {
			appLog.Debugf("%v is a directory (skip)", entry)
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".tar.gz") {
			appLog.Debugf("%v not a .tar.gz file (skip)", entry)
			continue
		}
		manifestData, err := util.ReadFileFromTarGz(archivePath, "alias.json")
		if err != nil {
			appLog.Errorf("Failed to read alias.json from '%s': %s", entry.Name(), err)
			continue
		}
		manifest := &AliasManifest{}
		err = json.Unmarshal(manifestData, manifest)
		if err != nil {
			appLog.Errorf("Error parsing alias manifest for '%s': %s", entry.Name(), err)
			continue
		}
		if strings.TrimSuffix(entry.Name(), ".tar.gz") != manifest.CommandName {
			appLog.Errorf("Invalid file name '%s' expected '%s'",
				entry.Name(), fmt.Sprintf("%s.tar.gz", manifest.CommandName),
			)
			continue
		}
		entries = append(entries, &api.ArmoryEntry{
			Name:        manifest.Name,
			CommandName: manifest.CommandName,
			RepoURL:     "",
			PublicKey:   "",
		})
		manifests[manifest.CommandName] = manifestData
	}
	return entries, manifests, nil
}

func getExtensions(rootDir string) ([]*api.ArmoryEntry, map[string][]byte, error) {
	appLog := log.GetAppLogger(rootDir)
	extensionsPath := filepath.Join(rootDir, consts.ExtensionsDirName)
	appLog.Infof("Looking for extensions in %s", extensionsPath)
	if _, err := os.Stat(extensionsPath); os.IsNotExist(err) {
		appLog.Errorf("Failed to find extensions: %s", err)
		return nil, nil, err
	}
	fi, err := os.ReadDir(extensionsPath)
	if err != nil {
		appLog.Errorf("Failed to find extensions: %s", err)
		return nil, nil, err
	}

	entries := []*api.ArmoryEntry{}
	manifests := map[string][]byte{}

	for _, entry := range fi {
		archivePath := filepath.Join(extensionsPath, entry.Name())
		if entry.IsDir() {
			appLog.Debugf("%v is a directory (skip)", entry)
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".tar.gz") {
			appLog.Debugf("%v not a .tar.gz file (skip)", entry)
			continue
		}
		manifestData, err := util.ReadFileFromTarGz(archivePath, "extension.json")
		if err != nil {
			appLog.Errorf("Failed to read extension.json from '%s': %s", entry.Name(), err)
			continue
		}
		manifest := &ExtensionManifest{}
		err = json.Unmarshal(manifestData, manifest)
		if err != nil {
			appLog.Errorf("Error parsing extension manifest for '%s': %s", entry.Name(), err)
			continue
		}
		if strings.TrimSuffix(entry.Name(), ".tar.gz") != manifest.CommandName {
			appLog.Errorf("Invalid file name '%s' expected '%s'",
				entry.Name(), fmt.Sprintf("%s.tar.gz", manifest.CommandName),
			)
			continue
		}
		entries = append(entries, &api.ArmoryEntry{
			Name:        manifest.Name,
			CommandName: manifest.CommandName,
			RepoURL:     "",
			PublicKey:   "",
		})
		manifests[manifest.CommandName] = manifestData
	}
	return entries, manifests, nil
}

func getBundles(rootDir string) ([]*api.ArmoryBundle, error) {
	bundles := []*api.ArmoryBundle{}
	bundleData, err := os.ReadFile(filepath.Join(rootDir, consts.BundlesFileName))
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		} else {
			return bundles, nil
		}
	}
	err = json.Unmarshal(bundleData, &bundles)
	return bundles, err
}
