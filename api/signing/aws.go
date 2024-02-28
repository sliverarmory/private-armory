package signing

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"aead.dev/minisign"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/sliverarmory/external-armory/consts"
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

	awsSession := session.Must(session.NewSession())
	smSvc := secretsmanager.New(awsSession, aws.NewConfig().WithRegion(keyInfoAWS.Region))
	secretInput := &secretsmanager.GetSecretValueInput{SecretId: aws.String(keyInfoAWS.Path)}

	result, err := smSvc.GetSecretValue(secretInput)
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
