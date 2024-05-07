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
	"strings"
	"time"

	"aead.dev/minisign"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/sliverarmory/private-armory/consts"
)

type VaultSigningProvider struct {
	privateKey  minisign.PrivateKey
	name        string
	initialized bool
}

type VaultSigningKeyInfo struct {
	Address      string
	AppRolePath  string
	AppRoleID    string
	AppSecretID  string
	VaultKeyPath string
	TLSEnabled   bool
	CustomCACert []byte
}

func (vski *VaultSigningKeyInfo) UnmarshalJSON(b []byte) error {
	var info map[string]string
	var ok bool

	if err := json.Unmarshal(b, &info); err != nil {
		return err
	}

	vski.Address, ok = info[consts.VaultAddrKey]
	if !ok {
		return errors.New("vault address not provided")
	}

	vski.AppRolePath, ok = info[consts.VaultAppRolePathKey]
	if !ok {
		return errors.New("vault approle path not provided")
	}

	vski.AppRoleID, ok = info[consts.VaultAppRoleIDKey]
	if !ok {
		return errors.New("vault approle ID not provided")
	}

	vski.AppSecretID, ok = info[consts.VaultAppSecretIDKey]
	if !ok {
		return errors.New("vault app secret ID not provided")
	}

	vski.VaultKeyPath, ok = info[consts.VaultKeyPathKey]
	if !ok {
		return errors.New("vault signing key path not provided")
	}

	return nil
}

func (vski *VaultSigningKeyInfo) MarshalJSON() ([]byte, error) {
	jsonData := map[string]string{
		consts.VaultAddrKey:        vski.Address,
		consts.VaultAppRolePathKey: vski.AppRolePath,
		consts.VaultAppRoleIDKey:   vski.AppRoleID,
		consts.VaultAppSecretIDKey: vski.AppSecretID,
		consts.VaultKeyPathKey:     vski.VaultKeyPath,
	}

	return json.Marshal(jsonData)
}

func (vsp *VaultSigningProvider) New(keyInfo SigningKeyInfo) error {
	var vaultClient *vault.Client
	var err error

	vsp.initialized = false
	vsp.name = consts.SigningKeyProviderVault

	keyInfoVault, ok := keyInfo.(*VaultSigningKeyInfo)
	if !ok {
		return errors.New("incorrect key information provided")
	}

	if keyInfoVault.TLSEnabled {
		tls := vault.TLSConfiguration{}
		if keyInfoVault.CustomCACert != nil {
			tls.ServerCertificate.FromBytes = keyInfoVault.CustomCACert
		}
		vaultClient, err = vault.New(
			vault.WithAddress(keyInfoVault.Address),
			vault.WithRequestTimeout(30*time.Second),
			vault.WithTLS(tls),
		)
	} else {
		vaultClient, err = vault.New(
			vault.WithAddress(keyInfoVault.Address),
			vault.WithRequestTimeout(30*time.Second),
		)
	}

	if err != nil {
		return err
	}

	resp, err := vaultClient.Auth.AppRoleLogin(
		context.Background(),
		schema.AppRoleLoginRequest{
			RoleId:   keyInfoVault.AppRoleID,
			SecretId: keyInfoVault.AppSecretID,
		},
		vault.WithMountPath(keyInfoVault.AppRolePath),
	)
	if err != nil {
		return err
	}

	if err := vaultClient.SetToken(resp.Auth.ClientToken); err != nil {
		return err
	}

	idx := strings.LastIndex(keyInfoVault.VaultKeyPath, "/")
	keyPath := keyInfoVault.VaultKeyPath[:idx]
	keyField := keyInfoVault.VaultKeyPath[idx+1:]
	keyResp, err := vaultClient.Read(context.Background(), keyPath)
	if err != nil {
		return err
	}

	keyData, ok := keyResp.Data[keyField].(string)
	if !ok {
		return fmt.Errorf("received unexpected data from vault for field %q (expected string)", keyField)
	}

	vsp.privateKey, err = minisign.DecryptKey("", []byte(keyData))
	if err != nil {
		return fmt.Errorf("could not decrypt key from vault: %s", err)
	}

	vsp.initialized = true
	return nil
}

func (vsp *VaultSigningProvider) Name() string {
	return vsp.name
}

func (vsp *VaultSigningProvider) Initialized() bool {
	return vsp.initialized
}

func (vsp *VaultSigningProvider) PublicKey() (string, error) {
	if !vsp.initialized {
		return "", errors.New("signing provider not initialized")
	}

	publicKey, ok := vsp.privateKey.Public().(minisign.PublicKey)
	if !ok {
		return "", errors.New("could not derive public key from the private key")
	}
	return publicKey.String(), nil
}

func (vsp *VaultSigningProvider) SignPackage(data, manifest []byte) ([]byte, error) {
	if !vsp.initialized {
		return nil, errors.New("signing provider not initialized")
	}

	encodedManifest := base64.StdEncoding.EncodeToString(manifest)
	return minisign.SignWithComments(vsp.privateKey, data, encodedManifest, ""), nil
}

func (vsp *VaultSigningProvider) SignIndex(indexData []byte) ([]byte, error) {
	if !vsp.initialized {
		return nil, errors.New("signing provider not initialized")
	}
	return minisign.Sign(vsp.privateKey, indexData), nil
}
