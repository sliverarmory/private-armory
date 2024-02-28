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
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"aead.dev/minisign"
	"github.com/AlecAivazis/survey/v2"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/sliverarmory/external-armory/util"
	"github.com/spf13/cobra"
)

var (
	ErrSigningKeyProviderRefused = errors.New("")
	// An error to signal that the signing key has already been decrypted
	ErrPackageSigningKeyDecrypted = errors.New("")
)

var genSignatureCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generate a package signing key",
	Run: func(cmd *cobra.Command, args []string) {
		var password string

		if cmd.Flags().Changed(consts.PasswordFlagStr) {
			fmt.Printf("\n" + Warn + Bold +
				"*** Keys generated with a non-blank password are not compatible with the AWS and Vault key providers *** " +
				Normal + Warn + "\n\n")
			err := survey.AskOne(&survey.Password{Message: "Private key password:"}, &password)
			if err != nil {
				fmt.Printf("\n" + Info + "user cancelled\n")
				return
			}
		} else {
			password = ""
		}

		public, private, err := minisign.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Printf(Warn+"failed to generate public/private key(s): %s", err)
			return
		}
		encryptedPrivateKey, err := minisign.EncryptKey(password, private)
		if err != nil {
			fmt.Printf(Warn+"failed to generate public/private key(s): %s", err)
			return
		}
		fileName, err := cmd.Flags().GetString(consts.FileFlagStr)
		if err != nil {
			fmt.Printf("%s error parsing flag --file, %s\n", Warn, err)
			return
		}
		if fileName != "" {
			err = os.WriteFile(fileName, encryptedPrivateKey, 0600)
			if err != nil {
				fmt.Printf("%s could not write key to %s: %s\n", Warn, fileName, err)
				return
			}
			fmt.Printf("%s wrote key to %s\n", Info, fileName)
		}
		fmt.Println("\n" + Info + "Package signing key successfully generated:")
		fmt.Printf("Public key:\n%s\n\n", public)
		fmt.Printf("Private key:\n%s\n\n", string(encryptedPrivateKey))
	},
}

// Gets a number from the user
func askForNumber(prompt string, min, max, defaultValue int) (int, error) {
	result := 0
	resultStr := ""

	numberQuestion := &survey.Question{
		Prompt: &survey.Input{Message: prompt},
		Validate: func(val interface{}) error {
			valStr, ok := val.(string)
			if !ok {
				return fmt.Errorf("invalid input")
			}
			// A blank string is okay - this means the user wants the default
			if valStr == "" {
				return nil
			}
			valNum, err := strconv.Atoi(valStr)
			if err != nil {
				return fmt.Errorf("%s is not a valid number", valStr)
			}
			if valNum < min || valNum > max {
				return fmt.Errorf("the number must be between %d and %d", min, max)
			}
			return nil
		},
	}

	err := survey.Ask([]*survey.Question{numberQuestion}, &resultStr)

	if err != nil {
		fmt.Printf("user cancelled entry - using default")
		result = defaultValue
		err = nil
	} else {
		// We would not have gotten here if the validation function did not pass, so we do not need to check the error
		if resultStr == "" {
			return defaultValue, nil
		} else {
			result, _ = strconv.Atoi(resultStr)
		}
	}

	return result, err
}

// Checks a given path to see if it is a directory, and if it is not, creates it
// The name parameter is a descriptive name and is used for informing the user
func checkAndCreateDirectory(name, path string) error {
	pathInfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		fmt.Printf(Info+"Creating %s directory: %s\n", name, path)
		return os.Mkdir(path, 0755)
	}
	if !pathInfo.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", path)
	}
	// Then the path exists and is a directory
	return nil
}

// Checks if a path is a directory
func checkDirectory(path string) bool {
	pathInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !pathInfo.IsDir() {
		return false
	}
	return true
}

// Checks to see if the application's directories are setup
func checkApplicationDirectories(rootDir string) bool {
	appDirs := []string{
		filepath.Join(rootDir, consts.ExtensionsDirName),
		filepath.Join(rootDir, consts.AliasesDirName),
		filepath.Join(rootDir, consts.SignaturesDirName),
		filepath.Join(rootDir, consts.CertificatesDirName),
	}

	for _, dir := range appDirs {
		if !checkDirectory(dir) {
			return false
		}
	}

	return true
}

// Gets the listening port for the server from the user or the environment
func getListeningPort() uint16 {
	var err error

	listenPort := consts.DefaultListenPort
	listenPortEnv, listenPortEnvSet := os.LookupEnv(consts.PortEnvVar)
	if !listenPortEnvSet {
		listenPort, err = askForNumber(fmt.Sprintf("Listening port (default: %d):", consts.DefaultListenPort), 1, math.MaxUint16, consts.DefaultListenPort)
	} else {
		listenPort, err = strconv.Atoi(listenPortEnv)
		if listenPort < 1 || listenPort > math.MaxUint16 || err != nil {
			listenPort, err = askForNumber(
				fmt.Sprintf("%s is not a valid port. Please input a different port (default: %d)", listenPortEnv, consts.DefaultListenPort),
				1,
				math.MaxUint16,
				consts.DefaultListenPort,
			)
		}
	}
	if err != nil {
		listenPort = consts.DefaultListenPort
	}

	return uint16(listenPort)
}

func getAndStoreSigningKey() error {
	var err error
	var signingProvider string

	// Check to see if the provider was passed in as an environment variable
	signingKeyProviderEnv, signingKeyProviderSet := os.LookupEnv(consts.SigningKeyProviderEnvVar)
	if signingKeyProviderSet {
		signingProvider = signingKeyProviderEnv
	} else if runningServerConfig.SigningKeyProviderName != "" {
		signingProvider = runningServerConfig.SigningKeyProviderName
	}
	if signingProvider != "" {
		switch signingProvider {
		case consts.SigningKeyProviderAWS:
			err = setupAWSKeyProvider()
			if err != nil {
				// Then the user needs to fix their config, so bail
				return fmt.Errorf("could not get package signing key from AWS: %s", err)
			}
		case consts.SigningKeyProviderVault:
			err = setupVaultKeyProvider()
			if err != nil {
				return fmt.Errorf("could not get package signing key from Vault: %s", err)
			}
		case consts.SigningKeyProviderExternal:
			err = setupExternalKeyProvider()
			if err != nil {
				return fmt.Errorf("could not set up external signing provider: %s", err)
			}
		default:
			// The provider is not supported or is local, fall back to file
			return setupLocalKeyProvider()
		}
	} else {
		// Go through each of the providers until we find the correct one
		err = setupAWSKeyProvider()
		if err != nil {
			if !errors.Is(err, ErrSigningKeyProviderRefused) {
				return fmt.Errorf("could not get package signing key from AWS: %s", err)
			}
		} else {
			return err // nil
		}
		err = setupVaultKeyProvider()
		if err != nil {
			if !errors.Is(err, ErrSigningKeyProviderRefused) {
				return fmt.Errorf("could not get package signing key from Vault: %s", err)
			}
		} else {
			return err // nil
		}
		err = setupExternalKeyProvider()
		if err != nil {
			if !errors.Is(err, ErrSigningKeyProviderRefused) {
				return fmt.Errorf("could not set up external signing provider: %s", err)
			}
		} else {
			return err // nil
		}
		fmt.Printf(Info + "Using a local package signing key\n")
		err = setupLocalKeyProvider()
	}
	return err
}

// Runs initial setup to make sure we have everything need to run the armory
func runSetup(flagsChanged []string) error {
	var err error

	directories := map[string]string{
		"extensions":   filepath.Join(runningServerConfig.RootDir, consts.ExtensionsDirName),
		"aliases":      filepath.Join(runningServerConfig.RootDir, consts.AliasesDirName),
		"signatures":   filepath.Join(runningServerConfig.RootDir, consts.SignaturesDirName),
		"certificates": filepath.Join(runningServerConfig.RootDir, consts.CertificatesDirName),
	}
	bundleFileName := filepath.Join(runningServerConfig.RootDir, consts.BundlesFileName)

	// Make sure the root directory is created first if it does not exist
	err = checkAndCreateDirectory("root", runningServerConfig.RootDir)
	if err != nil {
		return err
	}

	for name, dir := range directories {
		err = checkAndCreateDirectory(name, dir)
		if err != nil {
			return err
		}
	}

	fmt.Printf(Info+"Creating default bundle information file: %s\n", bundleFileName)
	err = os.WriteFile(bundleFileName, []byte(`[]`), 0644)
	if err != nil {
		return err
	}

	if !slices.Contains(flagsChanged, consts.DomainFlagStr) {
		domain, domainEnvSet := os.LookupEnv(consts.DomainEnvVar)
		if !domainEnvSet {
			survey.AskOne(&survey.Input{Message: "IP or domain name for clients to reach the armory (or blank for the internal IP of this host):"}, &domain)
		} else {
			domain = strings.Trim(domain, "\"")
		}

		runningServerConfig.DomainName = domain
	}

	if !slices.Contains(flagsChanged, consts.LportFlagStr) {
		runningServerConfig.ListenPort = getListeningPort()
	}

	runningServerConfig.TLSEnabled = checkIfTLSEnabled()

	fmt.Printf(Info+"Generating default configuration: %s\n", filepath.Join(runningServerConfig.RootDir, consts.ConfigFileName))

	err = getAndStoreSigningKey()
	if err != nil {
		return err
	}

	clientToken := ""
	clientTokenDigest := ""
	enableClientAuth := false

	// This is a bit confusing, but if the disable auth flag was changed, then the user wants to disable auth
	if !slices.Contains(flagsChanged, consts.DisableAuthFlagStr) {
		authChoiceEnv, authEnvSet := os.LookupEnv(consts.AuthEnabledEnvVar)
		if !authEnvSet {
			enableClientAuth = userConfirm("Enable client authentication?")
		} else {
			if authChoiceEnv == "1" {
				enableClientAuth = true
			}
		}
	} else {
		enableClientAuth = true
	}

	if enableClientAuth {
		clientToken, clientTokenDigest = randomAuthorizationToken()
	}
	runningServerConfig.ClientAuthenticationDisabled = !enableClientAuth
	runningServerConfig.ClientAuthorizationTokenDigest = clientTokenDigest

	adminToken, adminTokenDigest := randomAuthorizationToken()
	runningServerConfig.AdminAuthorizationTokenDigest = adminTokenDigest

	serverConfigData, _ := json.MarshalIndent(runningServerConfig, "", "  ")
	os.WriteFile(filepath.Join(runningServerConfig.RootDir, consts.ConfigFileName), serverConfigData, 0660)

	fmt.Println()
	pubKey, err := runningServerConfig.SigningKeyProvider.PublicKey()
	if err != nil {
		return err
	}
	userConfig, _ := json.MarshalIndent(&ArmoryClientConfig{
		PublicKey:     pubKey,
		RepoURL:       runningServerConfig.RepoURL() + "/" + path.Join("armory", "index"),
		Authorization: clientToken,
	}, "", "    ")
	fmt.Printf(Bold + "*** THIS WILL ONLY BE SHOWN ONCE ***\n")
	fmt.Printf(Bold+">>> User Config:%s\n%s\n\n", Normal, userConfig)
	fmt.Printf(Bold+">>> Admin Authentication Token (use this for adding, modifying, and deleting packages): %s\n%s\n", Normal, adminToken)

	return nil
}

func getPathToFileFromUser(prompt string) (string, error) {
	filePath := ""

	fileQuestion := &survey.Question{
		Prompt: &survey.Input{Message: prompt},
		Validate: func(val interface{}) error {
			strValue, ok := val.(string)
			if !ok {
				return fmt.Errorf("invalid input")
			}
			srcInfo, err := os.Stat(strValue)
			if os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist. Please input another file name", strValue)
			}
			if !srcInfo.Mode().IsRegular() {
				return fmt.Errorf("%s is not a file. Please input another file name", strValue)
			}
			if srcInfo.Size() == 0 {
				return fmt.Errorf("%s is an empty file. Please choose another file", strValue)
			}
			return nil
		},
	}
	err := survey.Ask([]*survey.Question{fileQuestion}, &filePath)
	return filePath, err
}

// Determines whether TLS is enabled, either by asking the user or looking at the TLS key files in their expected locations
func checkIfTLSEnabled() bool {
	var err error
	enableTLS := false

	// Look for the TLS key and cert
	tlsEnabledEnv, tlsEnabledSet := os.LookupEnv(consts.TLSEnabledEnvVar)
	defaultTLSKeyLocation := filepath.Join(runningServerConfig.RootDir, consts.TLSKeyPathFromRoot)
	defaultTLSCertLocation := filepath.Join(runningServerConfig.RootDir, consts.TLSCertPathFromRoot)

	if tlsEnabledSet {
		if tlsEnabledEnv != "1" {
			return enableTLS
		}
	}

	fileInfo, err := os.Stat(defaultTLSKeyLocation)

	if os.IsNotExist(err) {
		enableTLS = userConfirm("Enable TLS?")
		if !enableTLS {
			return enableTLS
		} else {
			tlsKeyPath, err := getPathToFileFromUser("Path to TLS private key file (Ctrl-C to cancel):")
			if err != nil {
				// Ctrl-C is returned as an error, so if we encounter any errors, then bail
				return enableTLS
			}
			err = util.CopyFile(tlsKeyPath, defaultTLSKeyLocation)
			if err != nil {
				fmt.Printf(Warn+"Could not copy TLS key file from %s to %s: %s. TLS will be disabled", tlsKeyPath, defaultTLSKeyLocation, err)
				return enableTLS
			}
		}
	} else if fileInfo.Size() == 0 {
		// Then the TLS key is an empty file, so we will disable TLS
		return enableTLS
	}

	fileInfo, err = os.Stat(defaultTLSCertLocation)
	if os.IsNotExist(err) {
		tlsCertPath, err := getPathToFileFromUser("Path to TLS certificate file (Ctrl-C to cancel):")
		if err != nil {
			return enableTLS
		}
		err = util.CopyFile(tlsCertPath, defaultTLSCertLocation)
		if err != nil {
			fmt.Printf(Warn+"Could not copy TLS key file from %s to %s: %s. TLS will be disabled", tlsCertPath, defaultTLSKeyLocation, err)
			return enableTLS
		}
	} else if fileInfo.Size() == 0 {
		// Without a valid key, we cannot enable TLS
		return enableTLS
	}

	return true
}

// Returns the password for the package signing key or gets it from the environment or user
func getUserSigningKeyPassword() (string, error) {
	if runningServerConfig != nil {
		if runningServerConfig.SigningKeyProvider != nil && runningServerConfig.SigningKeyProvider.Initialized() {
			// We have already decrypted the key, so we do not need the password
			return "", ErrPackageSigningKeyDecrypted
		}
	}

	armoryPasswordEnv, passwordEnvSet := os.LookupEnv(consts.SigningKeyPasswordEnvVar)
	if passwordEnvSet {
		return strings.Trim(armoryPasswordEnv, "\""), nil
	}
	password := ""
	prompt := &survey.Password{Message: "Private key password:"}
	survey.AskOne(prompt, &password)

	return password, nil
}

func userConfirm(msg string) bool {
	confirmed := false
	prompt := &survey.Confirm{Message: msg}
	survey.AskOne(prompt, &confirmed)
	return confirmed
}

func getDefaultRootDir() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(cwd, consts.ArmoryRootDirName), nil
}

func getRootDir(cmd *cobra.Command) (string, error) {
	rootDir, err := cmd.Flags().GetString(consts.RootDirFlagStr)
	if err != nil {
		// This usually happens if the cmd does not have a root-dir flag, so unless a config has been specified, assume the default root dir
		// The only command that calls this function and does not have a root-dir flag is refresh, and if the user wants to refresh an index
		// that does not live in the default root dir, they should be passing a config file
		rootDir = ""
	}
	if rootDir == "" {
		return getDefaultRootDir()
	} else {
		return rootDir, nil
	}
}
