package signing

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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"aead.dev/minisign"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/sliverarmory/private-armory/consts"
)

type AWSSigningProvider struct {
	privateKey  minisign.PrivateKey
	name        string
	initialized bool
}

type AWSSigningKeyInfo struct {
	Path   string
	Region string
}

func (aski *AWSSigningKeyInfo) UnmarshalJSON(b []byte) error {
	var info map[string]string
	var ok bool

	if err := json.Unmarshal(b, &info); err != nil {
		return err
	}

	aski.Path, ok = info[consts.AWSSecretNameKey]
	if !ok {
		return errors.New("key path not provided")
	}

	aski.Region, ok = info[consts.AWSRegionKey]
	if !ok {
		return errors.New("AWS region not provided")
	}

	return nil
}

func (aski *AWSSigningKeyInfo) MarshalJSON() ([]byte, error) {
	jsonData := map[string]string{
		consts.AWSSecretNameKey: aski.Path,
		consts.AWSRegionKey:     aski.Region,
	}
	return json.Marshal(jsonData)
}

func (asp *AWSSigningProvider) New(keyInfo SigningKeyInfo) error {
	asp.initialized = false
	asp.name = consts.SigningKeyProviderAWS

	keyInfoAWS, ok := keyInfo.(*AWSSigningKeyInfo)
	if !ok {
		return errors.New("incorrect key information provided")
	}

	smConfig, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(keyInfoAWS.Region))
	if err != nil {
		return fmt.Errorf("could not load AWS config: %s", err)
	}
	smClient := secretsmanager.NewFromConfig(smConfig)
	secretInput := &secretsmanager.GetSecretValueInput{SecretId: aws.String(keyInfoAWS.Path)}

	result, err := smClient.GetSecretValue(context.TODO(), secretInput)
	if err != nil {
		return fmt.Errorf("could not get key from AWS Secrets Manager: %s", err)
	}

	keyData := []byte(*result.SecretString)
	// Passwords are not used for AWS keys, so attempt to decrypt the key with a blank password
	asp.privateKey, err = minisign.DecryptKey("", keyData)
	if err != nil {
		return fmt.Errorf("could not decrypt key data: %s", err)
	}
	asp.initialized = true
	return nil
}

func (asp *AWSSigningProvider) Name() string {
	return asp.name
}

func (asp *AWSSigningProvider) Initialized() bool {
	return asp.initialized
}

func (asp *AWSSigningProvider) PublicKey() (string, error) {
	if !asp.initialized {
		return "", errors.New("signing provider not initialized")
	}

	publicKey, ok := asp.privateKey.Public().(minisign.PublicKey)
	if !ok {
		return "", errors.New("could not derive public key from the private key")
	}
	return publicKey.String(), nil
}

func (asp *AWSSigningProvider) SignPackage(data, manifest []byte) ([]byte, error) {
	if !asp.initialized {
		return nil, errors.New("signing provider not initialized")
	}

	encodedManifest := base64.StdEncoding.EncodeToString(manifest)
	return minisign.SignWithComments(asp.privateKey, data, encodedManifest, ""), nil
}

func (asp *AWSSigningProvider) SignIndex(indexData []byte) ([]byte, error) {
	if !asp.initialized {
		return nil, errors.New("signing provider not initialized")
	}
	return minisign.Sign(asp.privateKey, indexData), nil
}
