package signing

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"aead.dev/minisign"
	"github.com/sliverarmory/external-armory/consts"
)

const (
	signingKeyPathJSONKey     = "path"
	signingKeyPasswordJSONKey = "password"
)

type LocalSigningProvider struct {
	privateKey  minisign.PrivateKey
	name        string
	initialized bool
}

type LocalSigningKeyInfo struct {
	Path     string
	Password string
}

func (lski *LocalSigningKeyInfo) UnmarshalJSON(b []byte) error {
	var info map[string]string

	if err := json.Unmarshal(b, &info); err != nil {
		return err
	}

	lski.Path = info[signingKeyPathJSONKey]

	// Password is optional
	lski.Password = info[signingKeyPasswordJSONKey]

	return nil
}

func (lski *LocalSigningKeyInfo) MarshalJSON() ([]byte, error) {
	// The password is not going to go into the JSON object
	return json.Marshal([]byte{})
}

func generateAndStoreKey(path, password string) (minisign.PrivateKey, error) {
	_, privateKey, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return privateKey, fmt.Errorf("failed to generate new signing key: %s", err)
	}
	encryptedKey, err := minisign.EncryptKey(password, privateKey)
	if err != nil {
		return privateKey, fmt.Errorf("failed to encrypt new signing key: %s", err)
	}
	err = os.WriteFile(path, encryptedKey, 0600)
	if err != nil {
		return privateKey, fmt.Errorf("failed to write key to disk at %s: %s", path, err)
	}

	return privateKey, nil
}

func (lsp *LocalSigningProvider) New(keyInfo SigningKeyInfo) error {
	lsp.initialized = false
	lsp.name = consts.SigningKeyProviderLocal

	keyInfoLocal, ok := keyInfo.(*LocalSigningKeyInfo)
	if !ok {
		return errors.New("incorrect key information provided")
	}

	keyPathInfo, err := os.Stat(keyInfoLocal.Path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("could not get information about key at %s: %s", keyInfoLocal.Path, err)
		} else {
			// Create the key
			lsp.privateKey, err = generateAndStoreKey(keyInfoLocal.Path, keyInfoLocal.Password)
			if err != nil {
				return err
			}
		}
	} else {
		// The key exists
		if keyPathInfo.Size() == 0 {
			return fmt.Errorf("key %s is empty and needs to be regenerated", keyInfoLocal.Path)
		}
		keyData, err := os.ReadFile(keyInfoLocal.Path)
		if err != nil {
			return fmt.Errorf("could not read key file %s: %s", keyInfoLocal.Path, err)
		}

		lsp.privateKey, err = minisign.DecryptKey(keyInfoLocal.Password, keyData)
		if err != nil {
			return fmt.Errorf("could not decrypt private key with provided password: %s", err)
		}
	}

	lsp.initialized = true
	return nil
}

func (lsp *LocalSigningProvider) Name() string {
	return lsp.name
}

func (lsp *LocalSigningProvider) Initialized() bool {
	return lsp.initialized
}

func (lsp *LocalSigningProvider) PublicKey() (string, error) {
	if !lsp.initialized {
		return "", errors.New("signing provider not initialized")
	}

	publicKey, ok := lsp.privateKey.Public().(minisign.PublicKey)
	if !ok {
		return "", errors.New("could not derive public key from the private key")
	}
	return publicKey.String(), nil
}

func (lsp *LocalSigningProvider) SignPackage(data, manifest []byte) ([]byte, error) {
	if !lsp.initialized {
		return nil, errors.New("signing provider not initialized")
	}

	encodedManifest := base64.StdEncoding.EncodeToString(manifest)
	return minisign.SignWithComments(lsp.privateKey, data, encodedManifest, ""), nil
}

func (lsp *LocalSigningProvider) SignIndex(indexData []byte) ([]byte, error) {
	if !lsp.initialized {
		return nil, errors.New("signing provider not initialized")
	}
	return minisign.Sign(lsp.privateKey, indexData), nil
}

func (lsp *LocalSigningProvider) SetPrivateKey(key *minisign.PrivateKey) {
	lsp.privateKey = *key
	lsp.initialized = true
	lsp.name = consts.SigningKeyProviderLocal
}
