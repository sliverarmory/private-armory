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
	"os"

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
	FileName        string
	CopyToStorage   bool
	RawPrivateKey   []byte
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
	// File name and copy to storage are ephemeral, raw private key will not be output
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

func (lsp *LocalSigningProvider) readKeyFromStorageProvider(password string) error {
	if lsp.storageProvider == nil {
		return errors.New("storage provider is not initialized")
	}

	key, err := lsp.storageProvider.ReadPackageSigningKey()

	if err != nil {
		if !errors.Is(err, storage.ErrDoesNotExist) {
			return fmt.Errorf("could not get key from storage provider: %s", err)
		} else {
			// Create the key
			err = lsp.generateAndStoreKey(password)
			if err != nil {
				return err
			}
		}
	} else {
		// The key exists
		if len(key) == 0 {
			return errors.New("key is empty and needs to be regenerated")
		}

		lsp.privateKey, err = minisign.DecryptKey(password, key)
		if err != nil {
			return fmt.Errorf("could not decrypt private key with provided password: %s", err)
		}
	}
	return nil
}

func (lsp *LocalSigningProvider) readKeyFromLocalFileSystem(path, password string, copyToStorage bool) error {
	if path == "" {
		return errors.New("blank path provided")
	}

	keyData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read key from %q: %s", path, err)
	}

	if len(keyData) == 0 {
		return errors.New("key is empty and needs to be regenerated")
	}

	lsp.privateKey, err = minisign.DecryptKey(password, keyData)
	if err != nil {
		return fmt.Errorf("could not decrypt private key with provided password: %s", err)
	}

	if copyToStorage {
		if lsp.storageProvider == nil {
			return errors.New("cannot copy signing key to storage provider because the storage provider is not initialized")
		}
		err = lsp.storageProvider.WritePackageSigningKey(keyData)
		if err != nil {
			return fmt.Errorf("could not write signing key to provider: %s", err)
		}
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
	if keyInfoLocal.FileName != "" {
		err := lsp.readKeyFromLocalFileSystem(keyInfoLocal.FileName, keyInfoLocal.Password, keyInfoLocal.CopyToStorage)
		if err != nil {
			return err
		}
	} else if keyInfoLocal.RawPrivateKey != nil {
		err := lsp.setPrivateKeyFromBytes(keyInfoLocal.RawPrivateKey, keyInfoLocal.Password)
		if err != nil {
			return err
		}
	} else {
		err := lsp.readKeyFromStorageProvider(keyInfoLocal.Password)
		if err != nil {
			return err
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

func (lsp *LocalSigningProvider) setPrivateKeyFromBytes(keyData []byte, password string) error {
	var err error

	lsp.privateKey, err = minisign.DecryptKey(password, keyData)
	if err != nil {
		return fmt.Errorf("could not decrypt private key: %s", err)
	}
	lsp.initialized = true
	lsp.name = consts.SigningKeyProviderLocal
	return nil
}
