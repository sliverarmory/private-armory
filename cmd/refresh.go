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
	"errors"
	"fmt"
	"net/url"
	"path"

	"github.com/sirupsen/logrus"
	"github.com/sliverarmory/private-armory/api"
	"github.com/sliverarmory/private-armory/api/storage"
	"github.com/sliverarmory/private-armory/consts"
	"github.com/sliverarmory/private-armory/log"
	"github.com/spf13/cobra"
)

func runRefresh(appLog *logrus.Logger) {
	errors := refreshArmoryIndex()
	if len(errors) > 0 {
		errMsg := "Failed to refresh armory index:"
		fmt.Println(Warn + errMsg)
		appLog.Errorln(errMsg)
		for _, err := range errors {
			appLog.Errorln(err)
			fmt.Printf("%s%s\n", Warn, err)
		}
		return
	}
	appLog.Infoln("Successfully refreshed the package index")
	fmt.Println(Success + "Successfully refreshed the package index")
}

func invokeRefreshIndex(cmd *cobra.Command) {
	fmt.Printf(Info + "Refreshing armory index ...\n")
	err := getCommonInfoForSigningCmds(cmd)
	if err != nil {
		fmt.Println(Warn + "Refresh operation failed: " + err.Error())
		return
	}
	appLogFile, err := runningServerConfig.StorageProvider.GetLogger(consts.AppLogName)
	if err != nil {
		fmt.Printf("Failed to open app log: %s\n", err)
		return
	}
	// Closing the log is handled when the application exits (see cmd.Execute())
	appLog := log.StartLogger(appLogFile)
	logrus.RegisterExitHandler(shutdownStorage)
	appLog.Infoln("Refresh armory index invoked from command line")
	runRefresh(appLog)
}

var refreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Refresh the armory index",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		invokeRefreshIndex(cmd)
	},
}

func signArmoryIndex(data []byte) error {
	if runningServerConfig == nil {
		return ErrServerNotInitialized
	} else if runningServerConfig.SigningKeyProvider == nil {
		return ErrSigningProviderNotInitialized
	} else if runningServerConfig.StorageProvider == nil {
		return ErrStorageProviderNotInitialized
	}

	sig, err := runningServerConfig.SigningKeyProvider.SignIndex(data)
	if err != nil {
		return fmt.Errorf("failed to sign armory index: %s", err)
	}
	if sig == nil {
		// Then presumably the index was signed externally
		return nil
	}
	err = runningServerConfig.StorageProvider.WriteIndexSignature(sig)
	if err != nil {
		return fmt.Errorf("failed to write armory index signature: %s", err)
	}
	return nil
}

func refreshArmoryIndex() []error {
	if runningServerConfig == nil {
		return []error{ErrServerNotInitialized}
	} else if runningServerConfig.SigningKeyProvider == nil {
		return []error{ErrSigningProviderNotInitialized}
	}

	var index *api.ArmoryIndex
	var allErrors []error

	if !runningServerConfig.SigningKeyProvider.Initialized() {
		return []error{errors.New("cannot refresh armory index since no package signing key has been loaded")}
	}

	publicKey, err := runningServerConfig.SigningKeyProvider.PublicKey()
	if err != nil {
		return []error{fmt.Errorf("failed to retrieve public key from server configuration: %s", err)}
	}

	index, allErrors = generateArmoryIndex()
	if len(allErrors) != 0 {
		return allErrors
	}
	for _, entry := range index.Aliases {
		entry.PublicKey = publicKey
		entry.RepoURL, err = url.JoinPath(runningServerConfig.RepoURL(), "armory", consts.AliasesDirName, path.Base(entry.CommandName))
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("failed to create URL for alias %s: %s", entry.CommandName, err))
			continue
		}
	}
	for _, entry := range index.Extensions {
		entry.PublicKey = publicKey
		entry.RepoURL, err = url.JoinPath(runningServerConfig.RepoURL(), "armory", consts.ExtensionsDirName, path.Base(entry.CommandName))
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("failed to create URL for extension %s: %s", entry.CommandName, err))
			continue
		}
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		allErrors = append(allErrors, fmt.Errorf("failed to marshal armory index: %s", err))
		return allErrors
	}
	err = runningServerConfig.StorageProvider.WriteIndex(data)
	if err != nil {
		allErrors = append(allErrors, fmt.Errorf("failed to write armory index: %s", err))
		return allErrors
	}
	err = signArmoryIndex(data)
	if err != nil {
		allErrors = append(allErrors, err)
	}
	return allErrors
}

func signFile(manifest, fileDataToSign []byte) ([]byte, error) {
	if runningServerConfig == nil {
		return nil, ErrServerNotInitialized
	} else if runningServerConfig.SigningKeyProvider == nil {
		return nil, errors.New("a signing key provider is not available, so the package manifest cannot be signed")
	}

	sigData, err := runningServerConfig.SigningKeyProvider.SignPackage(fileDataToSign, manifest)
	if err != nil {
		return nil, err
	}
	return sigData, err
}

// GenerateArmoryIndex - Generate the armory index
func generateArmoryIndex() (*api.ArmoryIndex, []error) {
	if runningServerConfig == nil {
		return nil, []error{errors.New("the server is not configured, so an index cannot be generated")}
	} else if runningServerConfig.SigningKeyProvider == nil {
		return nil, []error{errors.New("a signing key provider is not available, so an index cannot be generated")}
	} else if runningServerConfig.StorageProvider == nil {
		return nil, []error{ErrStorageProviderNotInitialized}
	}

	var allErr []error
	aliasEntries := []*api.ArmoryEntry{}
	extensionEntries := []*api.ArmoryEntry{}

	aliasData, allErr := runningServerConfig.StorageProvider.ListPackages(consts.AliasPackageType)
	if len(allErr) != 0 {
		return nil, allErr
	}
	for aliasName, aliasEntry := range aliasData {
		fileDataToSign, err := runningServerConfig.StorageProvider.ReadPackage(aliasName)
		if err != nil {
			allErr = append(allErr, err)
			continue
		}
		packageSignature, err := signFile(aliasEntry.ManifestData, fileDataToSign)
		if err != nil {
			allErr = append(allErr, err)
			continue
		}
		err = runningServerConfig.StorageProvider.WritePackageSignature(aliasName, packageSignature)
		if err != nil {
			allErr = append(allErr, err)
			continue
		}
		aliasEntries = append(aliasEntries, &api.ArmoryEntry{
			Name:        aliasEntry.Name,
			CommandName: aliasEntry.CommandName,
		})
	}

	extensionManifests, allErr := runningServerConfig.StorageProvider.ListPackages(consts.ExtensionPackageType)
	if len(allErr) != 0 {
		return nil, allErr
	}

	for extensionName, extensionEntry := range extensionManifests {
		fileDataToSign, err := runningServerConfig.StorageProvider.ReadPackage(extensionName)
		if err != nil {
			allErr = append(allErr, err)
			continue
		}
		packageSignature, err := signFile(extensionEntry.ManifestData, fileDataToSign)
		if err != nil {
			allErr = append(allErr, err)
			continue
		}
		err = runningServerConfig.StorageProvider.WritePackageSignature(extensionName, packageSignature)
		if err != nil {
			allErr = append(allErr, err)
			continue
		}
		extensionEntries = append(extensionEntries, &api.ArmoryEntry{
			Name:        extensionEntry.Name,
			CommandName: extensionEntry.CommandName,
		})
	}

	bundles, err := getBundles()
	if err != nil {
		allErr = append(allErr, err)
		return nil, allErr
	}
	return &api.ArmoryIndex{
		Aliases:    aliasEntries,
		Extensions: extensionEntries,
		Bundles:    bundles,
	}, nil
}

func getBundles() ([]*api.ArmoryBundle, error) {
	bundles := []*api.ArmoryBundle{}
	bundleData, err := runningServerConfig.StorageProvider.ReadBundleFile()
	if err != nil {
		if !errors.Is(err, storage.ErrDoesNotExist) {
			return nil, err
		} else {
			return bundles, nil
		}
	}
	err = json.Unmarshal(bundleData, &bundles)
	return bundles, err
}
