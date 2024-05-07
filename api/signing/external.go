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
	"encoding/json"
	"errors"

	"github.com/sliverarmory/private-armory/consts"
)

const PublicKeyJSONKey = "public_key"

type ExternalSigningProvider struct {
	publicKey   string
	name        string
	initialized bool
}

type ExternalSigningKeyInfo struct {
	PublicKey string
}

func (eski *ExternalSigningKeyInfo) UnmarshalJSON(b []byte) error {
	var info map[string]string

	if err := json.Unmarshal(b, &info); err != nil {
		return err
	}

	publicKey, ok := info[PublicKeyJSONKey]
	if !ok {
		return errors.New("public key not provided")
	}

	eski.PublicKey = publicKey
	return nil
}

func (eski *ExternalSigningKeyInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{PublicKeyJSONKey: eski.PublicKey})
}

func (esp *ExternalSigningProvider) New(ski SigningKeyInfo) error {
	esp.initialized = false
	esp.name = consts.SigningKeyProviderExternal

	keyInfoExternal, ok := ski.(*ExternalSigningKeyInfo)
	if !ok {
		return errors.New("incorrect key information provided")
	}

	esp.publicKey = keyInfoExternal.PublicKey
	if esp.publicKey == "" {
		return errors.New("public key not provided")
	}

	esp.initialized = true
	return nil
}

func (esp *ExternalSigningProvider) Name() string {
	return esp.name
}

func (esp *ExternalSigningProvider) Initialized() bool {
	return esp.initialized
}

func (esp *ExternalSigningProvider) PublicKey() (string, error) {
	return esp.publicKey, nil
}

func (esp *ExternalSigningProvider) SignPackage(data, manifest []byte) ([]byte, error) {
	return nil, nil
}

func (esp *ExternalSigningProvider) SignIndex(data []byte) ([]byte, error) {
	return nil, nil
}
