package cmd

/*
	Sliver Implant Framework
	Copyright (C) 2024  Bishop Fox

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
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/sirupsen/logrus"
	"github.com/sliverarmory/external-armory/api/patterns"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/sliverarmory/external-armory/log"
	"github.com/sliverarmory/external-armory/util"
	"github.com/spf13/cobra"
)

func askForPassword() (string, error) {
	var password string
	err := survey.AskOne(&survey.Password{Message: "Private key password:"}, &password)
	if err != nil {
		fmt.Printf("\n" + Info + "user cancelled\n")
		return "", err
	}

	return password, nil
}

func getPasswordFromFile(path string) (string, error) {
	passwordFromFile, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(passwordFromFile), nil
}

func extractSigningPasswordFromCmdOrEnv(cmd *cobra.Command) (password string, err error) {
	password = ""

	promptPassword, err := cmd.Flags().GetBool(consts.PasswordFlagStr)
	if err != nil {
		err = fmt.Errorf(Warn+"could not parse flag --%s: %s", consts.PasswordFlagStr, err)
		return
	}
	if promptPassword {
		password, err = askForPassword()
		return
	} else if cmd.Flags().Changed(consts.PasswordFileFlagStr) {
		var passwordFilePath string
		passwordFilePath, err = cmd.Flags().GetString(consts.PasswordFileFlagStr)
		if err != nil {
			err = fmt.Errorf(Warn+"could not parse flag --%s: %s", consts.PasswordFileFlagStr, err)
			return
		}
		password, err = getPasswordFromFile(passwordFilePath)
		if err != nil {
			err = fmt.Errorf(Warn+"could not retrieve password from file %q: %s", passwordFilePath, err)
		}
	} else {
		armoryPasswordEnv, passwordEnvSet := os.LookupEnv(consts.SigningKeyPasswordEnvVar)
		if passwordEnvSet {
			password = strings.Trim(armoryPasswordEnv, "\"")
			err = nil
			return
		}
		// Then the password is blank, so return
	}
	return
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Package and index signing",
	Long:  "",
}

func signPackageStandalone(packagePath string) error {
	var manifestData []byte
	var packageType consts.PackageType
	var err error

	if runningServerConfig == nil {
		return ErrServerNotInitialized
	} else if runningServerConfig.SigningKeyProvider == nil {
		return ErrSigningProviderNotInitialized
	} else if runningServerConfig.StorageProvider == nil {
		return ErrStorageProviderNotInitialized
	}

	// Determine the type of package from the manifest and get the manifest
	packageData, err := os.ReadFile(packagePath)
	if err != nil {
		return fmt.Errorf("could not read from %q: %s", packagePath, err)
	}
	// Try alias first
	manifestData, err = util.ReadFileFromTarGzMemory(packageData, consts.AliasArchiveManifestFilePath)
	if err != nil {
		return fmt.Errorf("could not read from %q: %s", packagePath, err)
	}
	if manifestData == nil {
		// Then this may be an extension
		manifestData, err = util.ReadFileFromTarGzMemory(packageData, consts.ExtensionArchiveManifestFilePath)
		if err != nil {
			return fmt.Errorf("could not read from %q: %s", packagePath, err)
		}
		if manifestData == nil {
			// Then something is wrong with this file
			return fmt.Errorf("could not determine type of package for %q", packagePath)
		}
		packageType = consts.ExtensionPackageType
	} else {
		packageType = consts.AliasPackageType
	}

	packageName := strings.TrimSuffix(filepath.Base(packagePath), ".tar.gz")
	switch packageType {
	case consts.AliasPackageType:
		aliasManifest := &patterns.AliasManifest{}
		err := json.Unmarshal(manifestData, aliasManifest)
		if err != nil {
			return fmt.Errorf("could not parse package manifest: %s", err)
		}
	case consts.ExtensionPackageType:
		extensionManifest := &patterns.ExtensionManifestV1{}
		err := json.Unmarshal(manifestData, extensionManifest)
		if err != nil {
			// Try a V2 manifest
			extensionManifest := &patterns.ExtensionManifestV2{}
			err = json.Unmarshal(manifestData, extensionManifest)
			if err != nil {
				return fmt.Errorf("could not parse package manifest: %s", err)
			}
		}
	default:
		return errors.New("the package is not a supported type")
	}

	// Write the package to the armory
	err = runningServerConfig.StorageProvider.WritePackageWithFileName(filepath.Base(packagePath), packageData)
	if err != nil {
		return fmt.Errorf("could not write package to the storage provider: %s", err)
	}

	// By now, we have the manifest and file type
	// Start by signing it
	sigData, err := signFile(manifestData, packageData)
	if err != nil {
		return fmt.Errorf("could not sign package %s: %s", packageName, err)
	}

	// sigData should not be nil because our signing provider is not external
	if sigData == nil {
		return fmt.Errorf("signature was invalid")
	}
	sigErr := runningServerConfig.StorageProvider.WritePackageSignature(packageName, sigData)

	if sigErr != nil {
		// If the package signature could not be written, then delete the package too
		packageErr := runningServerConfig.StorageProvider.RemovePackage(packageName)
		if packageErr == nil {
			return fmt.Errorf("could not write package signature: %s", sigErr)
		} else {
			return fmt.Errorf("could not write package signature: %s; could not delete package %s: %s", sigErr, packageName, packageErr)
		}
	}
	return nil
}

func getSigningProviderFromCmd(cmd *cobra.Command) error {
	cannotSetExternal := errors.New("you must specify a signing key provider other than external")

	// Check the command line to see if a provider was set
	err := checkForCmdSigningProvider(cmd)
	if err != nil {
		return err
	} else if runningServerConfig.SigningKeyProviderName == consts.SigningKeyProviderExternal {
		// a nil error could mean that the flags were not set or the name was set to external
		return cannotSetExternal
	} else if runningServerConfig.SigningKeyProviderName != "" {
		// Then we got a signing provider other than external that was not blank
		fmt.Printf(Info+"Using %s signing provider\n", runningServerConfig.SigningKeyProviderName)
		return nil
	}

	// If we did not get a provider from the command line
	// Check to see if the provider was passed in as an environment variable
	signingKeyProviderEnv, signingKeyProviderSet := os.LookupEnv(consts.SigningKeyProviderEnvVar)
	if signingKeyProviderSet {
		if signingKeyProviderEnv == consts.SigningKeyProviderExternal {
			return cannotSetExternal
		}
		runningServerConfig.SigningKeyProviderName = signingKeyProviderEnv
		fmt.Printf(Info+"Using %s signing provider\n", runningServerConfig.SigningKeyProviderName)
		return nil
	}

	return errors.New("signing provider not set from the command line or environment")
}

func getCommonInfoForSigningCmds(cmd *cobra.Command) (err error) {
	var providerWasExternal bool
	var expectedPublicKey string

	err = initializeServerFromStorage(cmd)
	if err != nil {
		return
	}

	password, err := extractSigningPasswordFromCmdOrEnv(cmd)
	if err != nil {
		return
	}

	if runningServerConfig.SigningKeyProviderName == consts.SigningKeyProviderExternal {
		// If the configuration specifies an external key, we need to get an alternate signing provider
		fmt.Println(Info + "The configuration specifies an external signing key provider.")
		expectedPublicKey = runningServerConfig.PublicKey
		err = getSigningProviderFromCmd(cmd)
		if err != nil {
			return err
		}
		providerWasExternal = true
	}
	fmt.Println(Info + "Retrieving signing key from signing provider")
	err = getAndStoreSigningKey(password)
	if err != nil {
		err = fmt.Errorf(Warn+"could not get signing key from provider: %s", err)
		return
	}
	// If the configured signing provider was external, sanity check to make sure that the retrieved signing key
	// matches what we expect it to be
	if providerWasExternal {
		var publicKey string
		publicKey, err = runningServerConfig.SigningKeyProvider.PublicKey()
		if err != nil {
			err = fmt.Errorf("could not verify public key from provider: %s", err)
			return
		}
		if expectedPublicKey != publicKey {
			err = fmt.Errorf("signing key from provider does not match configured signing key")
			return
		}
	}
	return
}

func getInfoForPackageSigningCmd(cmd *cobra.Command) (filePath string, err error) {
	filePath, err = cmd.Flags().GetString(consts.FileFlagStr)
	if err != nil {
		err = fmt.Errorf(Warn+"could not parse flag --%s: %s", consts.FileFlagStr, err)
		return
	}
	err = getCommonInfoForSigningCmds(cmd)
	return
}

var signPackageCmd = &cobra.Command{
	Use:   "package",
	Short: "Sign a package",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		packagePath, err := getInfoForPackageSigningCmd(cmd)
		if err != nil {
			fmt.Println(Warn + err.Error())
			return
		}
		appLogFile, err := runningServerConfig.StorageProvider.GetLogger(consts.AppLogName)
		if err != nil {
			fmt.Println(Warn + err.Error())
			return
		}
		// Closing the logger is taken care of when this function returns to cmd.Execute()
		appLog := log.StartLogger(appLogFile)
		logrus.RegisterExitHandler(shutdownStorage)
		err = signPackageStandalone(packagePath)
		appLog.Infoln(fmt.Sprintf("Sign package invoked (%s)", filepath.Base(packagePath)))
		if err != nil {
			errorMsg := fmt.Sprintf("could not sign package %q: %s", packagePath, err)
			fmt.Println(Warn + errorMsg)
			appLog.Errorln(errorMsg)
			return
		}
		successMsg := fmt.Sprintf("Signed package %s successfully", filepath.Base(packagePath))
		appLog.Infoln(successMsg)
		fmt.Println(Success + successMsg)

		refresh, err := cmd.Flags().GetBool(consts.RefreshFlagStr)
		if err != nil {
			errorMsg := fmt.Sprintf("could not get refresh flag state: %s", err)
			fmt.Println(Warn + errorMsg)
			appLog.Errorln(errorMsg)
			return
		}
		if refresh {
			appLog.Infoln("Refresh package index invoked...")
			fmt.Println(Info + "Refreshing package index...")
			runRefresh(appLog)
		}
	},
}

var signIndexCmd = &cobra.Command{
	Use:   "index",
	Short: "Sign a package index",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		invokeRefreshIndex(cmd)
	},
}
