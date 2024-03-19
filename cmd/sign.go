package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"
	"github.com/AlecAivazis/survey/v2"
	"github.com/sirupsen/logrus"
	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/api/patterns"
	"github.com/sliverarmory/external-armory/api/signing"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/sliverarmory/external-armory/log"
	"github.com/sliverarmory/external-armory/util"
	"github.com/spf13/cobra"
)

func getSigningKey(password string) (*minisign.PrivateKey, string, error) {
	// The signing key can be provided through an environment variable or a file whose path is provided via the config file
	if runningServerConfig == nil {
		return nil, "all sources", ErrServerNotInitialized
	}

	var signingKeyData []byte
	var err error
	var privateKey minisign.PrivateKey
	var source string

	// Environment variable overrides config file
	signingKeyDataEnv, signingKeySet := os.LookupEnv(consts.SigningKeyEnvVar)

	if signingKeySet {
		source = fmt.Sprintf("environment variable %s", consts.SigningKeyEnvVar)
		signingKeyData = []byte(signingKeyDataEnv)
	} else {
		// Use the key from the config file
		source = "file from storage provider"
		signingKeyData, err = runningServerConfig.StorageProvider.ReadPackageSigningKey()
		if err != nil {
			return nil, source, err
		}
	}

	if len(signingKeyData) == 0 {
		return nil, "all sources", errors.New("signing key not provided")
	}

	if password == "" {
		// If the password from the command line was blank, the password may be in the environment variable
		// We can simply get the value because if the password is not defined in the environment, we will overwrite it with blank
		// which is fine because it is already blank
		password = os.Getenv(consts.SigningKeyPasswordEnvVar)
	}

	privateKey, err = minisign.DecryptKey(password, signingKeyData)
	if err != nil {
		return nil, source, fmt.Errorf("could not decrypt private key: %s", err)
	}

	return &privateKey, source, nil
}

func displayPublicKey(password string) {
	privateKey, source, err := getSigningKey(password)
	if err != nil {
		fmt.Printf(Warn+"error getting signing key from %s: %s\n", source, err)
		return
	}
	publicKey, ok := privateKey.Public().(minisign.PublicKey)
	if !ok {
		fmt.Printf(Warn+"could not derive public key from private key sourced from %s", source)
	}

	fmt.Printf(Info+"Using the private key sourced from %s, the public key is:\n\n", source)
	fmt.Printf("%s\n", publicKey.String())
}

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

func extractSigningPasswordFromCmd(cmd *cobra.Command) (password string, err error) {
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
	}
	return
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Package and index signing",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		password, err := extractSigningPasswordFromCmd(cmd)
		if err != nil {
			fmt.Println(err)
			return
		}
		displayPublicKey(password)
	},
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

func getCommonInfoForSigningCmds(cmd *cobra.Command) (err error) {
	storageProvider, configPath, err := getStorageProvider(cmd)
	if err != nil {
		return
	}

	runningServerConfig = &api.ArmoryServerConfig{
		StorageProvider: storageProvider,
	}

	err = getConfigDataFromStorageProvider(storageProvider, configPath)
	if err != nil {
		return
	}

	password, err := extractSigningPasswordFromCmd(cmd)
	if err != nil {
		return
	}
	signingKey, source, err := getSigningKey(password)
	if err != nil {
		err = fmt.Errorf(Warn+"could not get signing key from source %s: %s", source, err)
		return
	}

	// Create a local signing provider and inject the key
	provider := signing.LocalSigningProvider{}
	provider.SetPrivateKey(signingKey)

	// Assign the provider to the current config
	runningServerConfig.SigningKeyProvider = &provider
	runningServerConfig.SigningKeyProviderName = consts.SigningKeyProviderLocal

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
			fmt.Println(err)
			return
		}
		appLogFile, err := runningServerConfig.StorageProvider.GetLogger(consts.AppLogName)
		if err != nil {
			fmt.Println(err)
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
