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
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/api/signing"
	"github.com/sliverarmory/external-armory/api/storage"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/spf13/cobra"
)

// ArmoryClientConfig - The armory config file
type ArmoryClientConfig struct {
	PublicKey        string `json:"public_key"`
	RepoURL          string `json:"repo_url"`
	Authorization    string `json:"authorization"`
	AuthorizationCmd string `json:"authorization_cmd,omitempty"`
}

// Parses signing provider information received on the command line
// If required information is not provided, the function does not return an error because the necessary information
// may be provided later on through environment variables or asking the user
// Returns an error if an unsupported provider is requested
func parseSigningProviderOptions(signingProviderName string, signingProviderOptions map[string]string) (signing.SigningKeyInfo, error) {
	var err error

	switch signingProviderName {
	case consts.SigningKeyProviderAWS:
		awsConfigDetails := signing.AWSSigningKeyInfo{}
		awsConfigDetails.Path = signingProviderOptions[consts.AWSSecretNameKey]
		awsConfigDetails.Region = signingProviderOptions[consts.AWSRegionKey]
		return &awsConfigDetails, nil
	case consts.SigningKeyProviderExternal:
		externalConfigDetails := signing.ExternalSigningKeyInfo{}
		externalConfigDetails.PublicKey = signingProviderOptions[consts.ExternalPublicKeyKey]
		return &externalConfigDetails, nil
	case consts.SigningKeyProviderLocal:
		localConfigDetails := signing.LocalSigningKeyInfo{}
		localConfigDetails.Password = signingProviderOptions[consts.LocalKeyPasswordKey]
		return &localConfigDetails, nil
	case consts.SigningKeyProviderVault:
		vaultConfigDetails := signing.VaultSigningKeyInfo{}
		vaultConfigDetails.Address = signingProviderOptions[consts.VaultAddrKey]
		vaultConfigDetails.AppRoleID = signingProviderOptions[consts.VaultAppRoleIDKey]
		vaultConfigDetails.AppRolePath = signingProviderOptions[consts.VaultAppRolePathKey]
		vaultConfigDetails.AppSecretID = signingProviderOptions[consts.VaultAppSecretIDKey]
		vaultConfigDetails.VaultKeyPath = signingProviderOptions[consts.VaultKeyPathKey]
		caFileLocation, ok := signingProviderOptions[consts.VaultCustomCAPathKey]
		if ok {
			// Try to read the CA file from the local filesystem
			vaultConfigDetails.CustomCACert, err = os.ReadFile(caFileLocation)
			if err != nil {
				return nil, fmt.Errorf("could not read Vault CA PEM file from %q: %s", caFileLocation, err)
			}
		}
		return &vaultConfigDetails, nil
	default:
		return nil, fmt.Errorf("signing provider %q is not supported", signingProviderName)
	}
}

func checkForCmdSigningProvider(cmd *cobra.Command) error {
	var err error

	if !cmd.Flags().Changed(consts.SigningProviderNameFlagStr) {
		// If the signing provider name was not specified, then we will have to look at the config file and environment variables
		return nil
	}

	signingProviderName, err := cmd.Flags().GetString(consts.SigningProviderNameFlagStr)
	if err != nil {
		return fmt.Errorf("error parsing flag --%s, %s", consts.SigningProviderNameFlagStr, err)
	}

	signingProviderOptions, err := cmd.Flags().GetStringToString(consts.SigningProviderOptionsFlagStr)
	if err != nil {
		return fmt.Errorf("error parsing flag --%s, %s", consts.SigningProviderOptionsFlagStr, err)
	}

	// The signing key provider will be filled in once the details are verified (and a key is retrieved)
	runningServerConfig.SigningKeyProviderDetails, err = parseSigningProviderOptions(signingProviderName, signingProviderOptions)
	if err != nil {
		return err
	}
	runningServerConfig.SigningKeyProviderName = signingProviderName

	return nil
}

func getConfigDataFromStorageProvider(storageProvider storage.StorageProvider, configPath string) error {
	if storageProvider == nil {
		return ErrStorageProviderNotInitialized
	}

	if configPath != "" {
		parsedPath, err := url.Parse(configPath)
		if err != nil {
			return fmt.Errorf("could not parse config path: %s", err)
		}

		runningServerConfig.StorageProvider.SetConfigPath(parsedPath.Path)
	}

	configuredPaths, err := runningServerConfig.StorageProvider.Paths()
	if err != nil {
		return ErrServerNotInitialized
	}

	configData, err := runningServerConfig.StorageProvider.ReadConfig()
	if err != nil {
		if errors.Is(err, storage.ErrDoesNotExist) {
			fmt.Printf(Warn+"Config file %s does not exist\n", configuredPaths.Config)
		} else {
			fmt.Printf("Error reading config file %s, %s\n", configuredPaths.Config, err)
		}
		// Could not read a config file on disk for whatever reason, so we will use defaults and let CLI args override
		fmt.Println("Using default configuration and allowing command arguments to override")
	} else {
		err = json.Unmarshal(configData, runningServerConfig)
		if err != nil {
			// Something was wrong with the config file, the user will have to fix it or re-run setup
			return fmt.Errorf("error parsing config file %s, %s", configuredPaths.Config, err)
		}
	}

	return nil
}

func getServerConfig(cmd *cobra.Command) error {
	// We only need to pull configuration information if we do not currently have a config
	if runningServerConfig != nil {
		return nil
	}

	var err error

	// Keep track of the flags that we need to get from the environment or ask the user for
	flagsChanged := []string{}

	// Populate with defaults that can be changed by a config file or at the command line
	runningServerConfig = &api.ArmoryServerConfig{
		ListenPort:                     consts.DefaultListenPort,
		TLSEnabled:                     false,
		ClientAuthenticationDisabled:   true,
		ClientAuthorizationTokenDigest: "",
		ReadTimeout:                    time.Duration(5 * time.Minute),
		WriteTimeout:                   time.Duration(5 * time.Minute),
		SigningKeyProviderDetails:      nil,
	}

	storageProvider, configPath, err := getStorageProvider(cmd)
	if err != nil {
		return fmt.Errorf("could not determine root directory and start the server: %s", err)
	}

	runningServerConfig.StorageProvider = storageProvider
	runningServerConfig.StorageProviderName = storageProvider.Name()
	runningServerConfig.StorageProviderDetails = storageProvider.Options()

	err = getConfigDataFromStorageProvider(storageProvider, configPath)
	if err != nil {
		return err
	}

	// We need to check some CLI arguments in case setup needs to be run
	err = checkForCmdSigningProvider(cmd)
	if err != nil {
		return err
	}

	// CLI flags override config file
	if cmd.Flags().Changed(consts.DomainFlagStr) {
		runningServerConfig.DomainName, err = cmd.Flags().GetString(consts.DomainFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.DomainFlagStr, err)
		}
		flagsChanged = append(flagsChanged, consts.DomainFlagStr)
	}
	if cmd.Flags().Changed(consts.DisableAuthFlagStr) {
		runningServerConfig.ClientAuthenticationDisabled, err = cmd.Flags().GetBool(consts.DisableAuthFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.DisableAuthFlagStr, err)
		}
		flagsChanged = append(flagsChanged, consts.DisableAuthFlagStr)
	}
	if !runningServerConfig.ClientAuthenticationDisabled && runningServerConfig.ClientAuthorizationTokenDigest == "" {
		return fmt.Errorf("error cannot have blank authorization token, use --%s", consts.DisableAuthFlagStr)
	}

	if cmd.Flags().Changed(consts.LhostFlagStr) {
		runningServerConfig.ListenHost, err = cmd.Flags().GetString(consts.LhostFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.LhostFlagStr, err)
		}
		flagsChanged = append(flagsChanged, consts.LhostFlagStr)
	}

	if cmd.Flags().Changed(consts.LportFlagStr) {
		runningServerConfig.ListenPort, err = cmd.Flags().GetUint16(consts.LportFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.LportFlagStr, err)
		}
		flagsChanged = append(flagsChanged, consts.LportFlagStr)
	}

	if cmd.Flags().Changed(consts.EnableTLSFlagStr) {
		runningServerConfig.TLSEnabled, err = cmd.Flags().GetBool(consts.EnableTLSFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.EnableTLSFlagStr, err)
		}
		flagsChanged = append(flagsChanged, consts.EnableTLSFlagStr)
	}

	if cmd.Flags().Changed(consts.ReadTimeoutFlagStr) {
		readTimeoutStr, err := cmd.Flags().GetString(consts.ReadTimeoutFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.ReadTimeoutFlagStr, err)
		}
		readTimeout, err := time.ParseDuration(readTimeoutStr)
		if err != nil {
			return fmt.Errorf("invalid read timeout %q", readTimeoutStr)
		}
		runningServerConfig.ReadTimeout = readTimeout
		flagsChanged = append(flagsChanged, consts.ReadTimeoutFlagStr)
	}

	if cmd.Flags().Changed(consts.WriteTimeoutFlagStr) {
		writeTimeoutStr, err := cmd.Flags().GetString(consts.WriteTimeoutFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.WriteTimeoutFlagStr, err)
		}
		writeTimeout, err := time.ParseDuration(writeTimeoutStr)
		if err != nil {
			return fmt.Errorf("invalid write timeout %q", writeTimeoutStr)
		}
		runningServerConfig.WriteTimeout = writeTimeout
		flagsChanged = append(flagsChanged, consts.WriteTimeoutFlagStr)
	}

	// At this point, we should know where the root dir is
	// If the necessary directories are not setup, then we need to run setup
	if runningServerConfig.StorageProvider.IsNew() {
		err = runSetup(flagsChanged)
		if err != nil {
			// Remove the directories we created
			folderErr := runningServerConfig.StorageProvider.Destroy()
			if folderErr != nil {
				fmt.Printf("%s could not delete application root %q: %s\n", Warn, runningServerConfig.StorageProvider.BasePath(), folderErr)
			}
			runningServerConfig = nil
		}
		// Anything that would be overriden with the CLI has already been asked, so we are done
		return err
	} else {
		// This armory has been setup before, so we need to get the signing key
		getAndStoreSigningKey()
		if runningServerConfig.TLSEnabled {
			// Make sure we have the certificates set up properly if we are going to enable TLS
			// If it fails, make sure to update the config
			tlsEnabled := checkIfTLSEnabled()
			runningServerConfig.TLSEnabled = tlsEnabled
		}

		if cmd.Flags().Changed(consts.UpdateConfigFlagStr) {
			err = writeServerConfig()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func randomAuthorizationToken() (string, string) {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	hexToken := fmt.Sprintf("%x", buf)
	return hexToken, fmt.Sprintf("%x", sha256.Sum256([]byte(hexToken)))
}
