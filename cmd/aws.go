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
	"os"

	"aead.dev/minisign"
	"github.com/AlecAivazis/survey/v2"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/sliverarmory/external-armory/consts"
)

func retrieveSigningKeyDataFromSM() (string, error) {
	secretName := runningServerConfig.SigningKeyProviderDetails[consts.AWSSecretNameKey]
	region := runningServerConfig.SigningKeyProviderDetails[consts.AWSRegionKey]
	if secretName == "" || region == "" {
		return "", fmt.Errorf("AWS secret name and region must be specified")
	}
	fmt.Printf(Info+"Getting signing key from AWS (secret name %q from region %s)\n", secretName, region)
	awsSession := session.Must(session.NewSession())
	smSvc := secretsmanager.New(awsSession, aws.NewConfig().WithRegion(region))
	secretInput := &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretName)}
	result, err := smSvc.GetSecretValue(secretInput)
	if err != nil {
		return "", err
	}
	return *result.SecretString, nil
}

// Get the AWS region from the user
// The value is stored in the running server config
func getAWSRegionFromUser() {
	regionUser := ""
	survey.AskOne(&survey.Input{Message: fmt.Sprintf("AWS region name (default %s):", consts.DefaultAWSRegion)}, &regionUser)
	if regionUser == "" {
		runningServerConfig.SigningKeyProviderDetails[consts.AWSRegionKey] = consts.DefaultAWSRegion
	} else {
		runningServerConfig.SigningKeyProviderDetails[consts.AWSRegionKey] = regionUser
	}
}

// Attempts to get the package signing key from AWS SM
func getSigningKeyFromSM() error {
	if runningServerConfig == nil {
		return fmt.Errorf("server not initialized - run setup first")
	}
	awsKeyNameEnv, awsKeyNameSet := os.LookupEnv(consts.AWSKeySecretNameEnvVar)
	awsRegionEnv, awsRegionSet := os.LookupEnv(consts.AWSKeyRegionEnvVar)

	// Command line flag first (runningServerConfig.AWSKeySecretName will have the command line value if present)
	if runningServerConfig.SigningKeyProviderDetails[consts.AWSSecretNameKey] != "" {
		if runningServerConfig.SigningKeyProviderDetails[consts.AWSRegionKey] == "" {
			if awsRegionSet {
				runningServerConfig.SigningKeyProviderDetails[consts.AWSRegionKey] = awsRegionEnv
			} else {
				// Ask the user for the region
				getAWSRegionFromUser()
			}
		}
	} else if awsKeyNameSet {
		// Then environment variable
		runningServerConfig.SigningKeyProviderDetails[consts.AWSSecretNameKey] = awsKeyNameEnv
		if !awsRegionSet {
			getAWSRegionFromUser()
		} else {
			runningServerConfig.SigningKeyProviderDetails[consts.AWSRegionKey] = awsRegionEnv
		}
	} else {
		// Ask the user - if they say yes, then reach out to AWS
		getKeyFromAWS := userConfirm("Get package signing key from AWS Secrets Manager?")
		if getKeyFromAWS {
			secretName := ""
			survey.AskOne(&survey.Input{
				Message: "Secret name for signing key in Secrets Manager:",
			},
				&secretName,
				survey.WithValidator(survey.Required),
			)
			runningServerConfig.SigningKeyProviderDetails[consts.AWSSecretNameKey] = secretName
			if runningServerConfig.SigningKeyProviderDetails[consts.AWSRegionKey] == "" {
				if awsRegionSet {
					runningServerConfig.SigningKeyProviderDetails[consts.AWSRegionKey] = awsRegionEnv
				} else {
					getAWSRegionFromUser()
				}
			}
		} else {
			// If no, then we will have to find another provider
			return ErrSigningKeyProviderRefused
		}
	}
	// Reach out to AWS
	secretKey, err := retrieveSigningKeyDataFromSM()
	if err != nil {
		return err
	}
	// Try to decrypt the key - the password is blank
	decryptedKey, err := minisign.DecryptKey("", []byte(secretKey))
	if err != nil {
		return fmt.Errorf("could not decrypt key from Secrets Manager: %s", err)
	}
	pubKey, ok := decryptedKey.Public().(minisign.PublicKey)
	if !ok {
		return fmt.Errorf("could not derive public key from the private key")
	}
	runningServerConfig.SigningKey = &decryptedKey
	runningServerConfig.PublicKey = pubKey.String()
	runningServerConfig.SigningKeyProvider = consts.SigningKeyProviderAWS
	fmt.Printf(Info + "Successfully retrieved signing key from AWS")
	return nil
}
