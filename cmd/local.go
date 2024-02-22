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
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"aead.dev/minisign"
	"github.com/sliverarmory/external-armory/consts"
)

func generateEncryptedPackageSigningKey() (string, *minisign.PrivateKey, []byte, error) {
	publicKeyString := ""
	var privateKey minisign.PrivateKey
	var encryptedPrivateKey []byte

	public, privateKey, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return publicKeyString, nil, encryptedPrivateKey, fmt.Errorf(Warn+"failed to generate public/private key(s): %s", err)
	}

	publicKeyString = public.String()
	password, err := getUserSigningKeyPassword()
	if err != nil {
		return publicKeyString, nil, encryptedPrivateKey, fmt.Errorf("failed to get key password: %s", err)
	}
	encryptedPrivateKey, err = minisign.EncryptKey(password, privateKey)
	if err != nil {
		return publicKeyString, nil, encryptedPrivateKey, fmt.Errorf("failed to encrypt private key: %s", err)
	}

	return publicKeyString, &privateKey, encryptedPrivateKey, nil
}

// Generate a package signing key and store it in the running config
func generateAndStoreSignatureKey() error {
	public, privateKey, encryptedPrivateKey, err := generateEncryptedPackageSigningKey()
	if err != nil {
		return err
	}
	// If we are good, then set the running config appropriately
	runningServerConfig.PublicKey = public
	runningServerConfig.SigningKey = privateKey
	runningServerConfig.SigningKeyProvider = consts.SigningKeyProviderLocal
	return os.WriteFile(filepath.Join(runningServerConfig.RootDir, consts.LocalSigningKeyName), encryptedPrivateKey, 0600)
}

func fetchAndStoreLocalKey() error {
	// Check to see if local key exists
	if runningServerConfig == nil {
		return fmt.Errorf("server not initialized - run setup first")
	}
	localKeyPath := filepath.Join(runningServerConfig.RootDir, consts.LocalSigningKeyName)
	fileInfo, err := os.Stat(localKeyPath)
	if err != nil {
		return err
	}
	if fileInfo.Size() == 0 {
		return fmt.Errorf("key %s is empty and needs to be regenerated", localKeyPath)
	}
	// Key exists and has data in it, so let's see if we can decrypt it
	password, err := getUserSigningKeyPassword()
	if err != nil {
		return fmt.Errorf("could not get signing key password: %s", err)
	}
	keyData, err := os.ReadFile(localKeyPath)
	if err != nil {
		return fmt.Errorf("could not read key data from file %s: %s", localKeyPath, err)
	}
	key, err := minisign.DecryptKey(password, keyData)
	if err != nil {
		return fmt.Errorf("could not decrypt private key with provided password: %s", err)
	}
	pubKey, ok := key.Public().(minisign.PublicKey)
	if !ok {
		return fmt.Errorf("could not derive public key from the private key")
	}
	runningServerConfig.SigningKey = &key
	runningServerConfig.PublicKey = pubKey.String()
	runningServerConfig.SigningKeyProvider = consts.SigningKeyProviderLocal
	return nil
}

func getSigningKeyFromLocal() error {
	err := fetchAndStoreLocalKey()
	if err == nil || (err != nil && !errors.Is(err, os.ErrNotExist)) {
		return err
	}

	return generateAndStoreSignatureKey()
}
