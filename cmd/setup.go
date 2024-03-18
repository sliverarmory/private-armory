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
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"aead.dev/minisign"
	"github.com/AlecAivazis/survey/v2"
	"github.com/sliverarmory/external-armory/api"
	"github.com/sliverarmory/external-armory/api/storage"
	"github.com/sliverarmory/external-armory/consts"
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
			fmt.Printf("%s error parsing flag %s, %s\n", Warn, consts.FileFlagStr, err)
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

// Gets the listening port for the server from the user or the environment
func getListeningPort() uint16 {
	var err error

	listenPort := consts.DefaultListenPort
	listenPortEnv, listenPortEnvSet := os.LookupEnv(consts.PortEnvVar)
	if !listenPortEnvSet {
		listenPort, err = askForNumber(fmt.Sprintf("Listening port (default: %d):", consts.DefaultListenPort),
			1,
			math.MaxUint16,
			consts.DefaultListenPort,
		)
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

func generateClientToken() string {
	clientToken, clientTokenDigest := randomAuthorizationToken()

	runningServerConfig.ClientAuthorizationTokenDigest = clientTokenDigest

	return clientToken
}

func showClientConfig(pubKey, clientToken string) {
	fmt.Println()
	userConfig, _ := json.MarshalIndent(&ArmoryClientConfig{
		PublicKey:     pubKey,
		RepoURL:       runningServerConfig.RepoURL() + "/" + path.Join("armory", "index"),
		Authorization: clientToken,
	}, "", "    ")
	fmt.Printf(Bold + "*** THIS WILL ONLY BE SHOWN ONCE ***\n")
	fmt.Printf(Bold+">>> User Config:%s\n%s\n\n", Normal, userConfig)
}

func writeServerConfig() error {
	serverConfigData, _ := json.MarshalIndent(runningServerConfig, "", "  ")
	err := runningServerConfig.StorageProvider.WriteConfig(serverConfigData)
	if err != nil {
		return fmt.Errorf("could not write server config: %s", err)
	}

	return nil
}

// Runs initial setup to make sure we have everything need to run the armory
func runSetup(flagsChanged []string) error {
	if runningServerConfig == nil {
		return ErrServerNotInitialized
	}

	var err error
	var configPath string

	if runningServerConfig.StorageProvider != nil {
		storagePaths, err := runningServerConfig.StorageProvider.Paths()
		if err != nil {
			return ErrServerNotInitialized
		}
		configPath = storagePaths.Config
	}

	if configPath != "" {
		fmt.Printf(Info+"Generating configuration: %s\n", configPath)
	} else {
		fmt.Printf(Info + "Generating configuration\n")
	}

	if !slices.Contains(flagsChanged, consts.DomainFlagStr) {
		domain, domainEnvSet := os.LookupEnv(consts.DomainEnvVar)
		if !domainEnvSet {
			err = survey.AskOne(&survey.Input{Message: "IP or domain name for clients to reach the armory (or blank for the internal IP of this host):"}, &domain)
			if err != nil {
				return err
			}
		} else {
			domain = strings.Trim(domain, "\"")
		}

		runningServerConfig.DomainName = domain
	}

	if !slices.Contains(flagsChanged, consts.LportFlagStr) {
		runningServerConfig.ListenPort = getListeningPort()
	}

	// If this is the first setup, we still need to get the certificates from the user
	runningServerConfig.TLSEnabled = checkIfTLSEnabled()

	err = getAndStoreSigningKey()
	if err != nil {
		return err
	}

	clientToken := ""
	disableClientAuth := runningServerConfig.ClientAuthenticationDisabled

	// This is a bit confusing, but if the disable auth flag was changed, then the user wants to disable auth
	if !slices.Contains(flagsChanged, consts.DisableAuthFlagStr) {
		authChoiceEnv, authEnvSet := os.LookupEnv(consts.AuthEnabledEnvVar)
		if !authEnvSet {
			disableClientAuth = userConfirm("Disable client authentication?")
		} else {
			if authChoiceEnv != "1" {
				disableClientAuth = true
			}
		}
	}

	runningServerConfig.ClientAuthenticationDisabled = disableClientAuth

	if !disableClientAuth {
		clientToken = generateClientToken()
	}

	adminToken, adminTokenDigest := randomAuthorizationToken()
	runningServerConfig.AdminAuthorizationTokenDigest = adminTokenDigest

	err = writeServerConfig()
	if err != nil {
		return err
	}

	fmt.Println()
	pubKey, err := runningServerConfig.SigningKeyProvider.PublicKey()
	if err != nil {
		return err
	}
	showClientConfig(pubKey, clientToken)
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
	if runningServerConfig == nil {
		return false
	}

	var err error
	enableTLS := false

	// Look for the TLS key and cert
	tlsEnabledEnv, tlsEnabledSet := os.LookupEnv(consts.TLSEnabledEnvVar)

	if tlsEnabledSet {
		if tlsEnabledEnv != "1" {
			return enableTLS
		}
	}

	keyData, err := runningServerConfig.StorageProvider.ReadTLSCertificateKey()

	if errors.Is(err, storage.ErrDoesNotExist) {
		enableTLS = userConfirm("The TLS key does not exist in the expected location. Enable TLS?")
		if !enableTLS {
			return enableTLS
		} else {
			tlsKeyPath, err := getPathToFileFromUser("Path to TLS private key file (Ctrl-C to cancel):")
			if err != nil {
				// Ctrl-C is returned as an error, so if we encounter any errors, then bail
				return enableTLS
			}
			userKeyData, err := os.ReadFile(tlsKeyPath)
			if err != nil {
				fmt.Printf(Warn+"Could not read TLS key file from %s: %s. TLS will be disabled", tlsKeyPath, err)
				return enableTLS
			}
			err = runningServerConfig.StorageProvider.WriteTLSCertificateKey(userKeyData)
			if err != nil {
				fmt.Printf(Warn+"Could not copy TLS key file from %s to storage provider: %s. TLS will be disabled", tlsKeyPath, err)
				return enableTLS
			}
		}
	} else if err != nil {
		fmt.Printf(Warn+"Disabling TLS: could not read TLS key from storage provider: %s\n", err)
		return enableTLS
	} else if len(keyData) == 0 {
		// Then the TLS key is an empty file, so we will disable TLS
		fmt.Println(Warn + "Disabling TLS: TLS private key is empty")
		return enableTLS
	}

	crtData, err := runningServerConfig.StorageProvider.ReadTLSCertificateCrt()

	if errors.Is(err, storage.ErrDoesNotExist) {
		tlsCertPath, err := getPathToFileFromUser("Path to TLS certificate file (Ctrl-C to cancel):")
		if err != nil {
			return enableTLS
		}
		userCrtData, err := os.ReadFile(tlsCertPath)
		if err != nil {
			fmt.Printf(Warn+"Could not read TLS certificate file from %s: %s. TLS will be disabled", tlsCertPath, err)
			return enableTLS
		}
		err = runningServerConfig.StorageProvider.WriteTLSCertificateCrt(userCrtData)
		if err != nil {
			fmt.Printf(Warn+"Could not copy TLS certificate file from %s to storage provider: %s. TLS will be disabled", tlsCertPath, err)
			return enableTLS
		}
	} else if err != nil {
		fmt.Printf(Warn+"Disabling TLS: could not read TLS cert from storage provider: %s\n", err)
		return enableTLS
	} else if len(crtData) == 0 {
		// Without a valid cert, we cannot enable TLS
		fmt.Println(Warn + "Disabling TLS: TLS cert is empty")
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

func getDefaultLocalRootDir() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(cwd, consts.ArmoryRootDirName), nil
}

func getS3BucketRegion(bucketName string) (string, error) {
	// Try to get the region from the environment
	s3Region, s3RegionSet := os.LookupEnv(consts.AWSS3RegionEnvVar)
	if !s3RegionSet {
		err := survey.AskOne(&survey.Input{
			Message: fmt.Sprintf("Region for bucket %s:", bucketName),
			Default: "us-east-1",
		},
			&s3Region,
			survey.WithValidator(survey.Required),
		)
		if err != nil {
			return "", errors.New("canceled by user")
		}
	}
	return s3Region, nil
}

func initializeStorageProviderFromPath(path string) (storage.StorageProvider, error) {
	var storageProvider storage.StorageProvider
	var tempServerConfig api.ArmoryServerConfig

	parsedPath, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("could not parse path %q: %s", path, err)
	}

	switch parsedPath.Scheme {
	case consts.AWSS3StorageProviderStr:
		// The "host" is the bucket name
		bucketDir := strings.TrimPrefix(filepath.Dir(parsedPath.Path), "/")
		bucketConfigFilePath := strings.TrimPrefix(parsedPath.Path, "/")
		// Try to get the region
		region, err := getS3BucketRegion(parsedPath.Host)
		if err != nil {
			return nil, err
		}
		storageProvider = &storage.S3StorageProvider{}
		err = storageProvider.New(storage.S3StorageOptions{
			BucketName: parsedPath.Host,
			Directory:  bucketDir,
			Region:     region,
		}, true)
		if err != nil {
			return nil, err
		}
		// Try to get the config from the bucket
		err = storageProvider.SetConfigPath(bucketConfigFilePath)
		if err != nil {
			return nil, err
		}
		configData, err := storageProvider.ReadConfig()
		if err != nil {
			return nil, fmt.Errorf("error reading config file %q: %s", path, err)
		}
		err = json.Unmarshal(configData, &tempServerConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing config file %q: %s", path, err)
		}
	case "", "file":
		var localPath string
		// Then the path provided is on the local file system - we need to determine if it is a config file or a directory
		pathInfo, err := os.Stat(parsedPath.Path)
		if err != nil {
			return nil, fmt.Errorf("could not get info about %q: %s", path, err)
		}
		if !pathInfo.IsDir() {
			configData, err := os.ReadFile(parsedPath.Path)
			if err != nil {
				return nil, fmt.Errorf("could not read file %q: %s", path, err)
			}
			err = json.Unmarshal(configData, &tempServerConfig)
			if err != nil {
				// Something was wrong with the config file, the user will have to fix it or re-run setup
				return nil, fmt.Errorf("error parsing config file %q: %s", path, err)
			}
			localPath = tempServerConfig.RootDir
			if localPath == "" {
				return nil, fmt.Errorf("no root directory specified in configuration file %q", path)
			}
		} else {
			localPath = path
		}
		storageProvider = &storage.LocalStorageProvider{}
		err = storageProvider.New(storage.LocalStorageOptions{BasePath: localPath}, true)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%s is not a supported storage provider", parsedPath.Scheme)
	}

	return storageProvider, nil
}

func getStorageProvider(cmd *cobra.Command) (storage.StorageProvider, string, error) {
	var storageProvider storage.StorageProvider

	// Get the config path or root dir to try to bootstrap the storage provider
	configPath, err := cmd.Flags().GetString(consts.ConfigFlagStr)
	if err != nil {
		return nil, "", fmt.Errorf("error parsing flag --%s, %s", consts.ConfigFlagStr, err)
	}
	if configPath != "" {
		// Attempt to bootstrap the storage provider from the config file
		storageProvider, err = initializeStorageProviderFromPath(configPath)
		return storageProvider, configPath, err
	}

	rootDir, err := cmd.Flags().GetString(consts.RootDirFlagStr)
	if err != nil {
		// This usually happens if the cmd does not have a root-dir flag, so unless a config has been specified, assume the default root dir
		// The only command that calls this function and does not have a root-dir flag is refresh, and if the user wants to refresh an index
		// that does not live in the default root dir, they should be passing a config file
		rootDir = ""
	}

	if rootDir == "" {
		// Try to get the root dir from the environment
		rootDirEnv, rootDirEnvSet := os.LookupEnv(consts.RootDirEnvVar)
		if rootDirEnvSet {
			rootDir = rootDirEnv
		} else {
			rootDir, err = getDefaultLocalRootDir()
			if err != nil {
				return nil, "", err
			}
		}
	}

	// Determine what type of provider to set up based on the path passed in
	parsedDirPath, err := url.Parse(rootDir)
	if err != nil {
		return nil, "", fmt.Errorf("could not parse root directory path: %s", err)
	}
	switch parsedDirPath.Scheme {
	case consts.AWSS3StorageProviderStr:
		bucketDir := strings.TrimPrefix(parsedDirPath.Path, "/")
		storageProvider = &storage.S3StorageProvider{}
		// Try to get the region from the environment
		s3Region, err := getS3BucketRegion(parsedDirPath.Host)
		if err != nil {
			return nil, "", err
		}

		// The "host" is the bucket name
		storageOptions := storage.S3StorageOptions{
			BucketName: parsedDirPath.Host,
			Directory:  bucketDir,
			Region:     s3Region,
		}
		err = storageProvider.New(storageOptions, true)
		if err != nil {
			return nil, "", err
		}
	case "", "file":
		storageProvider = &storage.LocalStorageProvider{}
		storageOptions := storage.LocalStorageOptions{BasePath: parsedDirPath.Path}
		err = storageProvider.New(storageOptions, true)
		if err != nil {
			return nil, "", err
		}
	default:
		return nil, "", fmt.Errorf("%s is not a supported storage provider", parsedDirPath.Scheme)
	}

	providerPaths, err := storageProvider.Paths()
	if err != nil {
		return nil, "", err
	}
	runningServerConfig.RootDir = storageProvider.BasePath()
	return storageProvider, providerPaths.Config, nil
}
