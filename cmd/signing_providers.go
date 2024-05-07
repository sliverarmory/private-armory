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
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/sliverarmory/private-armory/api/signing"
	"github.com/sliverarmory/private-armory/consts"
)

/*
Local
*/
func setupLocalKeyProvider(password string) error {
	if runningServerConfig == nil {
		return ErrServerNotInitialized
	}

	var err error

	provider := &signing.LocalSigningProvider{}

	// Command line first (runningServerConfig.SigningKeyProviderDetails will be LocalSigningKeyInfo if it was set)
	localInfo, ok := runningServerConfig.SigningKeyProviderDetails.(*signing.LocalSigningKeyInfo)
	if !ok {
		localInfo = &signing.LocalSigningKeyInfo{}
		localInfo.Password = password
		signingKeyDataEnv, signingKeySet := os.LookupEnv(consts.SigningKeyEnvVar)
		if signingKeySet {
			localInfo.RawPrivateKey = []byte(signingKeyDataEnv)
		}
	}

	localInfo.StorageProvider = runningServerConfig.StorageProvider
	err = provider.New(localInfo)

	if err != nil {
		return err
	}

	publicKey, err := provider.PublicKey()
	if err != nil {
		return err
	}

	runningServerConfig.SigningKeyProvider = provider
	runningServerConfig.SigningKeyProviderName = consts.SigningKeyProviderLocal
	runningServerConfig.SigningKeyProviderDetails = nil
	runningServerConfig.PublicKey = publicKey

	return nil
}

/*
AWS
*/

// Get the AWS region from the user
// The value is stored in the running server config
func getAWSRegionFromUser() string {
	regionUser := ""
	survey.AskOne(&survey.Input{Message: fmt.Sprintf("AWS region name (default %s):", consts.DefaultAWSRegion)}, &regionUser)
	if regionUser == "" {
		return consts.DefaultAWSRegion
	} else {
		return regionUser
	}
}

// Attempts to get the package signing key from AWS SM
func setupAWSKeyProvider() error {
	if runningServerConfig == nil {
		return ErrServerNotInitialized
	}

	awsKeyNameEnv, awsKeyNameSet := os.LookupEnv(consts.AWSKeySecretNameEnvVar)
	awsRegionEnv, awsRegionSet := os.LookupEnv(consts.AWSKeyRegionEnvVar)

	var err error
	var awsKeyInfo *signing.AWSSigningKeyInfo

	// Command line flag first (runningServerConfig.SigningKeyProviderDetails will be AWSSigningKeyInfo if it was set)
	awsKeyInfo, ok := runningServerConfig.SigningKeyProviderDetails.(*signing.AWSSigningKeyInfo)
	if !ok {
		awsKeyInfo = &signing.AWSSigningKeyInfo{}
		if awsKeyNameSet {
			awsKeyInfo.Path = awsKeyNameEnv
			if !awsRegionSet {
				awsKeyInfo.Region = getAWSRegionFromUser()
			} else {
				awsKeyInfo.Region = awsRegionEnv
			}
		} else {
			// Ask the user - if they say yes, then reach out to AWS
			getKeyFromAWS := userConfirm("Get package signing key from AWS Secrets Manager?")
			if getKeyFromAWS {
				err = survey.AskOne(&survey.Input{
					Message: "Secret name for signing key in Secrets Manager:",
				},
					&awsKeyInfo.Path,
					survey.WithValidator(survey.Required),
				)
				if err != nil {
					return ErrSigningKeyProviderRefused
				}
				if !awsRegionSet {
					awsKeyInfo.Region = getAWSRegionFromUser()
				} else {
					awsKeyInfo.Region = awsRegionEnv
				}
			} else {
				// If no, then we will have to find another provider
				return ErrSigningKeyProviderRefused
			}
		}
	}

	provider := signing.AWSSigningProvider{}
	err = provider.New(awsKeyInfo)
	if err != nil {
		return err
	}
	publicKey, err := provider.PublicKey()
	if err != nil {
		return err
	}

	runningServerConfig.SigningKeyProvider = &provider
	runningServerConfig.SigningKeyProviderName = consts.SigningKeyProviderAWS
	runningServerConfig.SigningKeyProviderDetails = awsKeyInfo
	runningServerConfig.PublicKey = publicKey

	fmt.Println(Info + "Successfully retrieved signing key from AWS")
	return nil
}

/*
Vault
*/

func askForVaultURL() (string, error) {
	userURL := ""

	urlQuestion := &survey.Question{
		Prompt: &survey.Input{Message: "Vault address / URL:"},
		Validate: func(val interface{}) error {
			urlStr, ok := val.(string)
			if !ok {
				return fmt.Errorf("invalid input")
			}
			_, err := url.Parse(urlStr)
			return err
		},
	}

	err := survey.Ask([]*survey.Question{urlQuestion}, &userURL)
	if err != nil {
		// Then the user probably canceled
		return "", err
	}
	return userURL, nil
}

func vaultUsesTLS(urlStr string) bool {
	parsedUrl, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return strings.ToLower(parsedUrl.Scheme) == "https"
}

func setupVaultKeyProvider() error {
	if runningServerConfig == nil {
		return ErrServerNotInitialized
	}

	var err error

	vaultAddrEnv, vaultAddrSet := os.LookupEnv(consts.VaultAddrEnvVar)
	vaultAppRolePathEnv, vaultAppRolePathSet := os.LookupEnv(consts.VaultAppRolePathEnvVar)
	vaultAppRoleIDEnv, vaultAppRoleIDSet := os.LookupEnv(consts.VaultRoleIDEnvVar)
	vaultAppSecretIDEnv, vaultAppSecretIDSet := os.LookupEnv(consts.VaultSecretIDEnvVar)
	vaultKeyPathEnv, vaultKeyPathSet := os.LookupEnv(consts.VaultSigningKeyPathEnvVar)

	vaultKeyInfo, ok := runningServerConfig.SigningKeyProviderDetails.(*signing.VaultSigningKeyInfo)
	if !ok {
		vaultKeyInfo = &signing.VaultSigningKeyInfo{}
		if vaultAddrSet {
			vaultKeyInfo.Address = vaultAddrEnv
		} else {
			// Determine if the user wants to use Vault as the signing key provider
			getKeyFromVault := userConfirm("Get package signing key from Vault?")
			if !getKeyFromVault {
				return ErrSigningKeyProviderRefused
			}
			// Get the info from the user
			vaultKeyInfo.Address, err = askForVaultURL()
			if err != nil {
				return err
			}
		}
	}
	// Any command line values should be populated already, so fill in the gaps
	vaultKeyInfo.TLSEnabled = vaultUsesTLS(vaultKeyInfo.Address)
	// Check to see if we need to use a custom CA file
	if vaultKeyInfo.TLSEnabled {
		// If the PEM file for the CA has been supplied from the command line, then use that
		if vaultKeyInfo.CustomCACert != nil {
			err = runningServerConfig.StorageProvider.WriteVaultCA(vaultKeyInfo.CustomCACert)
			if err != nil {
				return fmt.Errorf("could not write custom CA certificate to storage provider: %s", err)
			}
		} else {
			// Check to see if the storage provider has CA data in it already
			vaultKeyInfo.CustomCACert, err = runningServerConfig.StorageProvider.ReadVaultCA()
			if err != nil {
				getCustomCA := userConfirm("Do you need to supply a custom CA PEM file?")
				if getCustomCA {
					caFilePath, err := getPathToFileFromUser("Path to custom CA PEM file (Ctrl-C to cancel):")
					if err == nil {
						// For future runs of the server, it is easier we keep the file at the default path
						caData, err := os.ReadFile(caFilePath)
						if err != nil {
							return fmt.Errorf("could not read custom CA PEM file: %s", err)
						}
						err = runningServerConfig.StorageProvider.WriteVaultCA(caData)
						if err != nil {
							return fmt.Errorf("could not write custom CA certificate to storage provider: %s", err)
						}
						vaultKeyInfo.CustomCACert = caData
					} else {
						return fmt.Errorf("cancelled by user")
					}
				}
			}
		}

	}

	// The app role path is optional, but if it is not filled in, we do not know
	// if the user is accepting the default or needs to enter something
	if vaultKeyInfo.AppRolePath == "" {
		if vaultAppRolePathSet {
			vaultKeyInfo.AppRolePath = vaultAppRolePathEnv
		} else {
			// Get the info from the user
			err = survey.AskOne(&survey.Input{Message: "Vault app role path (default: approle):"}, &vaultKeyInfo.AppRolePath)
			if err != nil {
				return ErrSigningKeyProviderRefused
			}
			if vaultKeyInfo.AppRolePath == "" {
				vaultKeyInfo.AppRolePath = consts.VaultDefaultAppRolePath
			}
		}
	}

	if vaultKeyInfo.AppRoleID == "" {
		if vaultAppRoleIDSet {
			vaultKeyInfo.AppRoleID = vaultAppRoleIDEnv
		} else {
			err = survey.AskOne(&survey.Input{
				Message: "Vault AppRole Role ID (UUID):",
			},
				&vaultKeyInfo.AppRoleID,
				survey.WithValidator(survey.Required),
			)
			if err != nil {
				return ErrSigningKeyProviderRefused
			}
		}
	}

	if vaultKeyInfo.AppSecretID == "" {
		if vaultAppSecretIDSet {
			vaultKeyInfo.AppSecretID = vaultAppSecretIDEnv
		} else {
			err = survey.AskOne(&survey.Password{
				Message: "Vault AppRole Secret ID (UUID):",
			},
				&vaultKeyInfo.AppSecretID, survey.WithValidator(survey.Required),
			)
			if err != nil {
				return ErrSigningKeyProviderRefused
			}
		}
	}

	if vaultKeyInfo.VaultKeyPath == "" {
		if vaultKeyPathSet {
			vaultKeyInfo.VaultKeyPath = vaultKeyPathEnv
		} else {
			err = survey.AskOne(&survey.Input{
				Message: "Vault Signing Key Path (path to the key with the field at the end - path/to/key/field):",
			},
				&vaultKeyInfo.VaultKeyPath,
				survey.WithValidator(survey.Required),
			)
			if err != nil {
				return ErrSigningKeyProviderRefused
			}
		}
	}

	provider := signing.VaultSigningProvider{}
	err = provider.New(vaultKeyInfo)
	if err != nil {
		return err
	}

	publicKey, err := provider.PublicKey()
	if err != nil {
		return err
	}

	runningServerConfig.SigningKeyProvider = &provider
	runningServerConfig.SigningKeyProviderName = consts.SigningKeyProviderVault
	runningServerConfig.SigningKeyProviderDetails = vaultKeyInfo
	runningServerConfig.PublicKey = publicKey

	fmt.Println(Info + "Successfully retrieved signing key from Vault")
	return nil
}

/*
External
*/
func setupExternalKeyProvider() error {
	if runningServerConfig == nil {
		return ErrServerNotInitialized
	}
	var err error

	externalKeyEnv, externalKeySet := os.LookupEnv(consts.ExternalPublicKeyEnvVar)

	externalKeyInfo, ok := runningServerConfig.SigningKeyProviderDetails.(*signing.ExternalSigningKeyInfo)
	if !ok {
		externalKeyInfo = &signing.ExternalSigningKeyInfo{}
		if externalKeySet {
			externalKeyInfo.PublicKey = strings.Trim(externalKeyEnv, "\"")
		} else {
			// Ask the user
			getKeyFromExternal := userConfirm("Use an external process to sign packages and the index?")
			if !getKeyFromExternal {
				return ErrSigningKeyProviderRefused
			}
			err = survey.AskOne(&survey.Input{
				Message: "Minisign Public Key:"},
				&externalKeyInfo.PublicKey,
				survey.WithValidator(survey.Required),
			)
			if err != nil {
				return ErrSigningKeyProviderRefused
			}
		}
	}

	provider := signing.ExternalSigningProvider{}
	err = provider.New(externalKeyInfo)
	if err != nil {
		return err
	}

	publicKey, err := provider.PublicKey()
	if err != nil {
		// External signing providers do not return errors for public keys, but
		// in case the function ever changes, we will be prepared
		return err
	}

	runningServerConfig.SigningKeyProvider = &provider
	runningServerConfig.SigningKeyProviderDetails = externalKeyInfo
	runningServerConfig.SigningKeyProviderName = consts.SigningKeyProviderExternal
	runningServerConfig.PublicKey = publicKey

	return nil
}
