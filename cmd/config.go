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
	"os"
	"path/filepath"
	"time"

	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/api/signing"
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

func checkForCmdSigningProvider(cmd *cobra.Command) error {
	var err error

	// The signing key provider will be filled in once the details are verified (and a key is retrieved)
	if cmd.Flags().Changed(consts.AWSSigningKeySecretNameFlagStr) {
		awsConfigDetails := signing.AWSSigningKeyInfo{}

		awsConfigDetails.Path, err = cmd.Flags().GetString(consts.AWSSigningKeySecretNameFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.AWSSigningKeySecretNameFlagStr, err)
		}
		awsConfigDetails.Region, err = cmd.Flags().GetString(consts.AWSRegionFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.AWSRegionFlagStr, err)
		}

		runningServerConfig.SigningKeyProviderDetails = &awsConfigDetails
	} else if cmd.Flags().Changed(consts.VaultURLFlagStr) {
		vaultConfigDetails := signing.VaultSigningKeyInfo{}

		vaultURL, err := cmd.Flags().GetString(consts.VaultURLFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.VaultURLFlagStr, err)
		}
		vaultConfigDetails.Address = vaultURL

		vaultApprolePath, err := cmd.Flags().GetString(consts.VaultAppRolePathFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.VaultAppRolePathFlagStr, err)
		}
		vaultConfigDetails.AppRolePath = vaultApprolePath

		vaultRoleID, err := cmd.Flags().GetString(consts.VaultRoleIDFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.VaultRoleIDFlagStr, err)
		}
		vaultConfigDetails.AppRoleID = vaultRoleID

		vaultSecretID, err := cmd.Flags().GetString(consts.VaultSecretIDFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.VaultSecretIDFlagStr, err)
		}
		vaultConfigDetails.AppSecretID = vaultSecretID

		vaultPath, err := cmd.Flags().GetString(consts.VaultKeyPathFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.VaultKeyPathFlagStr, err)
		}
		vaultConfigDetails.VaultKeyPath = vaultPath

		runningServerConfig.SigningKeyProviderDetails = &vaultConfigDetails
	} else if cmd.Flags().Changed(consts.PublicKeyFlagStr) {
		externalSignerDetails := signing.ExternalSigningKeyInfo{}
		publicKey, err := cmd.Flags().GetString(consts.PublicKeyFlagStr)
		if err != nil {
			return fmt.Errorf("error parsing flag --%s, %s", consts.PublicKeyFlagStr, err)
		}
		externalSignerDetails.PublicKey = publicKey
		runningServerConfig.SigningKeyProviderDetails = &externalSignerDetails
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
	runningServerConfig.RootDir, err = getRootDir(cmd)
	if err != nil {
		return fmt.Errorf("could not determine root directory and start the server: %s", err)
	}
	configPath, err := cmd.Flags().GetString(consts.ConfigFlagStr)
	if err != nil {
		return fmt.Errorf("error parsing flag --%s, %s", consts.ConfigFlagStr, err)
	}
	if configPath == "" {
		cwd, _ := os.Getwd()
		configPath = filepath.Join(cwd, consts.ArmoryRootDirName, consts.ConfigFileName)
		if runningServerConfig.RootDir == "" {
			runningServerConfig.RootDir = filepath.Join(cwd, consts.ArmoryRootDirName)
		}
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf(Warn+"Config file %s does not exist\n", configPath)
		} else {
			fmt.Printf("Error reading config file %s, %s\n", configPath, err)
		}
		// Could not read a config file on disk for whatever reason, so we will use defaults and let CLI args override
		fmt.Println("Using default configuration and allowing command arguments to override")
	} else {
		err = json.Unmarshal(configData, runningServerConfig)
		if err != nil {
			// Something was wrong with the config file, the user will have to fix it or re-run setup
			return fmt.Errorf("error parsing config file %s, %s", configPath, err)
		}
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
	if !checkApplicationDirectories(runningServerConfig.RootDir) {
		err = runSetup(flagsChanged)
		if err != nil {
			// Remove the directories we created
			folderErr := os.RemoveAll(runningServerConfig.RootDir)
			if folderErr != nil {
				fmt.Printf("%s could not delete application directory %s: %s\n", Warn, runningServerConfig.RootDir, folderErr)
			}
			runningServerConfig = nil
		}
		// Anything that would be overriden with the CLI has already been asked, so we are done
		return err
	} else {
		// This armory has been setup before, so we need to get the signing key
		getAndStoreSigningKey()
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
