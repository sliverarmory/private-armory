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
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aead.dev/minisign"
	"github.com/AlecAivazis/survey/v2"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/sliverarmory/external-armory/consts"
)

func retrieveSigningKeyDataFromVault(tlsEnabled, customCAEnabled bool) (string, error) {
	providerDetails := runningServerConfig.SigningKeyProviderDetails
	var vaultClient *vault.Client
	var err error

	// Create a Vault client
	if tlsEnabled {
		tls := vault.TLSConfiguration{}
		if customCAEnabled {
			tls.ServerCertificate.FromFile = filepath.Join(runningServerConfig.RootDir, consts.VaultCAPathFromRoot)
		}
		vaultClient, err = vault.New(
			vault.WithAddress(providerDetails[consts.VaultAddrKey]),
			vault.WithRequestTimeout(30*time.Second),
			vault.WithTLS(tls),
		)
	} else {
		vaultClient, err = vault.New(
			vault.WithAddress(providerDetails[consts.VaultAddrKey]),
			vault.WithRequestTimeout(30*time.Second),
		)
	}

	if err != nil {
		return "", err
	}
	resp, err := vaultClient.Auth.AppRoleLogin(
		context.Background(),
		schema.AppRoleLoginRequest{
			RoleId:   providerDetails[consts.VaultAppRoleIDKey],
			SecretId: providerDetails[consts.VaultAppSecretIDKey],
		},
		vault.WithMountPath(providerDetails[consts.VaultAppRolePathKey]),
	)
	if err != nil {
		return "", err
	}

	if err := vaultClient.SetToken(resp.Auth.ClientToken); err != nil {
		return "", err
	}

	idx := strings.LastIndex(providerDetails[consts.VaultKeyPathKey], "/")
	keyPath := providerDetails[consts.VaultKeyPathKey][:idx]
	keyField := providerDetails[consts.VaultKeyPathKey][idx+1:]
	keyResp, err := vaultClient.Read(context.Background(), keyPath)
	if err != nil {
		return "", err
	}
	keyData, ok := keyResp.Data[keyField].(string)
	if !ok {
		return "", fmt.Errorf("received unexpected data from vault for field %q (expected string)", keyField)
	}
	return keyData, nil
}

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

func getSigningKeyFromVault() error {
	if runningServerConfig == nil {
		return fmt.Errorf("server not initialized - run setup first")
	}
	vaultProviderDetails := runningServerConfig.SigningKeyProviderDetails
	vaultAddrEnv, vaultAddrSet := os.LookupEnv(consts.VaultAddrEnvVar)
	vaultAppRolePathEnv, vaultAppRolePathSet := os.LookupEnv(consts.VaultAppRolePathEnvVar)
	vaultAppRoleIDEnv, vaultAppRoleIDSet := os.LookupEnv(consts.VaultRoleIDEnvVar)
	vaultAppSecretIDEnv, vaultAppSecretIDSet := os.LookupEnv(consts.VaultSecretIDEnvVar)
	vaultKeyPathEnv, vaultKeyPathSet := os.LookupEnv(consts.VaultSigningKeyPathEnvVar)

	tlsEnabled := false
	useCustomCA := false

	customCAPath := filepath.Join(runningServerConfig.RootDir, consts.VaultCAPathFromRoot)

	// Any command line values should be populated already, so fill in the gaps
	if vaultProviderDetails[consts.VaultAddrKey] == "" {
		if vaultAddrSet {
			vaultProviderDetails[consts.VaultAddrKey] = vaultAddrEnv
		} else {
			// Determine if the user wants to use Vault as the signing key provider
			getKeyFromVault := userConfirm("Get package signing key from Vault?")
			if !getKeyFromVault {
				return ErrSigningKeyProviderRefused
			}
			// Get the info from the user
			vaultAddr, err := askForVaultURL()
			if err != nil {
				return err
			}
			vaultProviderDetails[consts.VaultAddrKey] = vaultAddr
			tlsEnabled = vaultUsesTLS(vaultAddr)
			if tlsEnabled {
				getCustomCA := userConfirm("Do you need to supply a custom CA PEM file?")
				if getCustomCA {
					caFilePath, err := getPathToFileFromUser("Path to custom CA PEM file (Ctrl-C to cancel):")
					if err == nil {
						copyErr := copyFile(caFilePath, customCAPath)
						if copyErr != nil {
							return fmt.Errorf("could not copy custom CA PEM file to application root: %s", err)
						}
						useCustomCA = true
					} else {
						return fmt.Errorf("cancelled by user")
					}
				}
			}
		}
	}

	// Check to see if we need to use a custom CA file
	// This is for docker instances and runs of the server after initial setup
	if vaultUsesTLS(vaultProviderDetails[consts.VaultAddrKey]) {
		tlsEnabled = true
		// If the PEM file for the CA has been supplied, then use that
		if _, err := os.Stat(customCAPath); err == nil {
			useCustomCA = true
		}
	}

	// The app role path is optional, but if it is not filled in, we do not know
	// if the user is accepting the default or needs to enter something
	if vaultProviderDetails[consts.VaultAppRolePathKey] == "" {
		if vaultAppRolePathSet {
			vaultProviderDetails[consts.VaultAppRolePathKey] = vaultAppRolePathEnv
		} else {
			// Get the info from the user
			vaultAppRolePath := ""
			survey.AskOne(&survey.Input{Message: "Vault app role path (default: approle):"}, &vaultAppRolePath)
			vaultProviderDetails[consts.VaultAppRolePathKey] = vaultAppRolePath
		}
	}

	if vaultProviderDetails[consts.VaultAppRoleIDKey] == "" {
		if vaultAppRoleIDSet {
			vaultProviderDetails[consts.VaultAppRoleIDKey] = vaultAppRoleIDEnv
		} else {
			vaultAppRoleID := ""
			survey.AskOne(&survey.Input{Message: "Vault AppRole Role ID (UUID):"}, &vaultAppRoleID, survey.WithValidator(survey.Required))
			vaultProviderDetails[consts.VaultAppRoleIDKey] = vaultAppRoleID
		}
	}

	if vaultProviderDetails[consts.VaultAppSecretIDKey] == "" {
		if vaultAppSecretIDSet {
			vaultProviderDetails[consts.VaultAppSecretIDKey] = vaultAppSecretIDEnv
		} else {
			vaultAppSecretID := ""
			survey.AskOne(&survey.Input{Message: "Vault AppRole Secret ID (UUID):"}, &vaultAppSecretID, survey.WithValidator(survey.Required))
			vaultProviderDetails[consts.VaultAppSecretIDKey] = vaultAppSecretID
		}
	}

	if vaultProviderDetails[consts.VaultKeyPathKey] == "" {
		if vaultKeyPathSet {
			vaultProviderDetails[consts.VaultKeyPathKey] = vaultKeyPathEnv
		} else {
			vaultKeyPath := ""
			survey.AskOne(&survey.Input{
				Message: "Vault Signing Key Path (path to the key with the field at the end - path/to/key/field):",
			},
				&vaultKeyPath,
				survey.WithValidator(survey.Required),
			)
			vaultProviderDetails[consts.VaultKeyPathKey] = vaultKeyPath
		}
	}

	signingKeyVault, err := retrieveSigningKeyDataFromVault(tlsEnabled, useCustomCA)
	if err != nil {
		return err
	}
	// Try to decrypt the key, password is blank
	decryptedKey, err := minisign.DecryptKey("", []byte(signingKeyVault))
	if err != nil {
		return fmt.Errorf("could not decrypt key from vault: %s", err)
	}
	pubKey, ok := decryptedKey.Public().(minisign.PublicKey)
	if !ok {
		return fmt.Errorf("could not derive public key from the private key")
	}
	runningServerConfig.SigningKey = &decryptedKey
	runningServerConfig.PublicKey = pubKey.String()
	runningServerConfig.SigningKeyProviderDetails = vaultProviderDetails
	runningServerConfig.SigningKeyProvider = consts.SigningKeyProviderVault
	fmt.Printf(Info + "Successfully retrieved signing key from Vault")
	return nil
}
