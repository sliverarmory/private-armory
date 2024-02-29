package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"
	"github.com/AlecAivazis/survey/v2"
	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/api/signing"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/sliverarmory/external-armory/util"
	"github.com/spf13/cobra"
)

func getSigningKey(path, password string) (*minisign.PrivateKey, string, error) {
	// The signing key can be provided through an environment variable or a file whose path is provided on the command line

	var signingKeyData []byte
	var err error
	var privateKey minisign.PrivateKey
	var source string

	// The command line overrides the environment variable
	if path != "" {
		source = fmt.Sprintf("file %q", path)
		signingKeyData, err = os.ReadFile(path)
		if err != nil {
			return nil, path, fmt.Errorf("could not read key from path %q: %s", source, err)
		}
	} else {
		source = fmt.Sprintf("environment variable %s", consts.SigningKeyEnvVar)
		signingKeyDataEnv, signingKeySet := os.LookupEnv(consts.SigningKeyEnvVar)
		if !signingKeySet {
			return nil, consts.SigningKeyEnvVar, fmt.Errorf("signing key not provided")
		}
		signingKeyData = []byte(signingKeyDataEnv)
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

func displayPublicKey(path, password string) {
	privateKey, source, err := getSigningKey(path, password)
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

func extractSigningKeyInfoFromCmd(cmd *cobra.Command) (keyPath string, password string, err error) {
	keyPath, err = cmd.Flags().GetString(consts.KeyFlagStr)
	if err != nil {
		err = fmt.Errorf(Warn+"could not parse flag --%s: %s", consts.KeyFlagStr, err)
		return keyPath, password, err
	}
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
		keyPath, password, err := extractSigningKeyInfoFromCmd(cmd)
		if err != nil {
			fmt.Println(err)
			return
		}
		displayPublicKey(keyPath, password)
	},
}

func signPackageStandalone(packagePath string) error {
	var manifest []byte
	var packageType consts.PackageType
	var copyPath string
	var err error

	if runningServerConfig == nil {
		return fmt.Errorf("the application has not been initialized properly")
	} else if runningServerConfig.SigningKeyProvider == nil {
		return fmt.Errorf("the application has not been initialized properly")
	}

	// Check that the root directory exists
	rootDirInfo, err := os.Stat(runningServerConfig.RootDir)
	if err != nil {
		return fmt.Errorf("could not get information on root directory %q: %s", runningServerConfig.RootDir, err)
	}
	if !rootDirInfo.IsDir() {
		return fmt.Errorf("%q is not a directory", runningServerConfig.RootDir)
	}

	// Determine the type of package from the manifest and get the manifest
	// Try alias first
	manifest, err = util.ReadFileFromTarGz(packagePath, consts.AliasManifestFileName)
	if err != nil {
		return fmt.Errorf("could not read from %q: %s", packagePath, err)
	}
	if manifest == nil {
		// Then this may be an extension
		manifest, err = util.ReadFileFromTarGz(packagePath, consts.ExtensionManifestFileName)
		if err != nil {
			return fmt.Errorf("could not read from %q: %s", packagePath, err)
		}
		if manifest == nil {
			// Then something is wrong with this file
			return fmt.Errorf("could not determine type of package for %q", packagePath)
		}
		packageType = consts.ExtensionPackageType
	} else {
		packageType = consts.AliasPackageType
	}

	// By now, we have the manifest and file type
	// Start by signing it
	err = signFile(manifest, packagePath)
	if err != nil {
		return fmt.Errorf("could not sign file %q: %s", packagePath, err)
	}

	// Copy the package to the appropriate directory
	switch packageType {
	case consts.AliasPackageType:
		copyPath = filepath.Join(runningServerConfig.RootDir, consts.AliasesDirName, filepath.Base(packagePath))
	case consts.ExtensionPackageType:
		copyPath = filepath.Join(runningServerConfig.RootDir, consts.ExtensionsDirName, filepath.Base(packagePath))
	}
	err = util.CopyFile(packagePath, copyPath)
	if err != nil {
		firstError := fmt.Sprintf("could not copy package to %q: %s", copyPath, err)
		// Try to delete the signature
		sigPath := filepath.Join(runningServerConfig.RootDir, consts.SignaturesDirName, filepath.Base(strings.TrimSuffix(packagePath, ".tar.gz")))
		err = os.Remove(sigPath)
		if err != nil {
			return fmt.Errorf("encountered two errors:\n%s\ncould not remove signature %q: %s", firstError, sigPath, err)
		} else {
			return fmt.Errorf(firstError)
		}
	}
	return nil
}

func getCommonInfoForSigningCmds(cmd *cobra.Command) (err error) {
	configPath, err := cmd.Flags().GetString(consts.ConfigFlagStr)
	if err != nil {
		err = fmt.Errorf("error parsing flag --%s, %s", consts.ConfigFlagStr, err)
		return
	}
	// Reconstitute the configuration
	configData, err := os.ReadFile(configPath)
	if err != nil {
		err = fmt.Errorf("could not read config from %q: %s", configPath, err)
		return
	}
	runningServerConfig = &api.ArmoryServerConfig{}

	err = json.Unmarshal(configData, runningServerConfig)
	if err != nil {
		// Something was wrong with the config file, the user will have to fix it
		err = fmt.Errorf("error parsing config file %q: %s", configPath, err)
		return
	}

	keyPath, password, err := extractSigningKeyInfoFromCmd(cmd)
	if err != nil {
		return
	}
	signingKey, source, err := getSigningKey(keyPath, password)
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
		err = signPackageStandalone(packagePath)
		if err != nil {
			fmt.Printf(Warn+"could not sign package %q: %s\n", packagePath, err)
			return
		}
		fmt.Printf(Success+"Signed package %s successfully\n", filepath.Base(packagePath))
	},
}

var signIndexCmd = &cobra.Command{
	Use:   "index",
	Short: "Sign a package index",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		err := getCommonInfoForSigningCmds(cmd)
		if err != nil {
			fmt.Println(err)
			return
		}
		errors := refreshArmoryIndex()
		if len(errors) > 0 {
			for _, err := range errors {
				fmt.Printf("%s%s\n", Warn, err)
			}
			return
		}
		fmt.Println(Success + "Refreshed and signed index")
	},
}
