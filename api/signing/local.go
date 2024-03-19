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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"aead.dev/minisign"
	"github.com/sliverarmory/external-armory/api/storage"
	"github.com/sliverarmory/external-armory/consts"
)

const (
	signingKeyPathJSONKey     = "path"
	signingKeyPasswordJSONKey = "password"
)

type LocalSigningProvider struct {
	privateKey      minisign.PrivateKey
	storageProvider storage.StorageProvider
	name            string
	initialized     bool
}

type LocalSigningKeyInfo struct {
	Password        string
	StorageProvider storage.StorageProvider
}

func (lski *LocalSigningKeyInfo) UnmarshalJSON(b []byte) error {
	var info map[string]string

	if err := json.Unmarshal(b, &info); err != nil {
		return err
	}

	// Password is optional
	lski.Password = info[signingKeyPasswordJSONKey]

	return nil
}

func (lski *LocalSigningKeyInfo) MarshalJSON() ([]byte, error) {
	// The password is not going to go into the JSON object
	return json.Marshal([]byte{})
}

func (lsp *LocalSigningProvider) generateAndStoreKey(password string) error {
	var err error

	_, lsp.privateKey, err = minisign.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate new signing key: %s", err)
	}
	encryptedKey, err := minisign.EncryptKey(password, lsp.privateKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt new signing key: %s", err)
	}
	err = lsp.storageProvider.WritePackageSigningKey(encryptedKey)
	if err != nil {
		return fmt.Errorf("failed to write key to storage provider: %s", err)
	}

	return nil
}

func (lsp *LocalSigningProvider) New(keyInfo SigningKeyInfo) error {
	lsp.initialized = false
	lsp.name = consts.SigningKeyProviderLocal

	keyInfoLocal, ok := keyInfo.(*LocalSigningKeyInfo)
	if !ok {
		return errors.New("incorrect key information provided")
	}

	lsp.storageProvider = keyInfoLocal.StorageProvider

	key, err := lsp.storageProvider.ReadPackageSigningKey()

	if err != nil {
		if !errors.Is(err, storage.ErrDoesNotExist) {
			return fmt.Errorf("could not get key from storage provider: %s", err)
		} else {
			// Create the key
			err = lsp.generateAndStoreKey(keyInfoLocal.Password)
			if err != nil {
				return err
			}
		}
	} else {
		// The key exists
		if len(key) == 0 {
			return errors.New("key is empty and needs to be regenerated")
		}

		lsp.privateKey, err = minisign.DecryptKey(keyInfoLocal.Password, key)
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
