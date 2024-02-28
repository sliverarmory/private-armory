package consts

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

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

const (
	ArmoryRootDirName   = "armory-data"
	ExtensionsDirName   = "extensions"
	AliasesDirName      = "aliases"
	BundlesFileName     = "bundles.json"
	ConfigFileName      = "config.json"
	CertificatesDirName = "certificates"
	TLSKeyPathFromRoot  = CertificatesDirName + "/armory.key"
	TLSCertPathFromRoot = CertificatesDirName + "/armory.crt"
	DefaultListenPort   = 8888
	DefaultAWSRegion    = "us-west-2"
	LocalSigningKeyName = "private.key"
	VaultCAPathFromRoot = CertificatesDirName + "/armory-vault-ca.pem"

	// Command line flags
	LhostFlagStr        = "lhost"
	LportFlagStr        = "lport"
	ConfigFlagStr       = "config"
	WriteTimeoutFlagStr = "write-timeout"
	ReadTimeoutFlagStr  = "read-timeout"
	DisableAuthFlagStr  = "disable-authentication"
	RefreshFlagStr      = "refresh"
	DomainFlagStr       = "domain"
	EnableTLSFlagStr    = "enable-tls"

	RootDirFlagStr = "root-dir"

	// API
	ArchivePathName         = "archive"
	AliasPathVariable       = "alias_name"
	ExtensionPathVariable   = "extension_name"
	PackageTypePathVariable = "package_type"
	PackageNamePathVariable = "package_name"

	// AWS
	AWSSigningKeySecretNameFlagStr = "aws-key-name"
	AWSRegionFlagStr               = "aws-region"

	// Vault
	VaultURLFlagStr         = "vault-url"
	VaultAppRolePathFlagStr = "vault-approle-path"
	VaultRoleIDFlagStr      = "vault-role-id"
	VaultSecretIDFlagStr    = "vault-secret-id"
	VaultKeyPathFlagStr     = "vault-path"
	VaultDefaultAppRolePath = "approle"

	// Environment variables
	SigningKeyPasswordEnvVar  = "ARMORY_SIGNING_KEY_PASSWORD"
	PortEnvVar                = "ARMORY_PORT"
	DomainEnvVar              = "ARMORY_DOMAIN_NAME"
	AuthEnabledEnvVar         = "ARMORY_AUTHENTICATION_ENABLED"
	TLSEnabledEnvVar          = "ARMORY_TLS_ENABLED"
	SigningKeyProviderEnvVar  = "ARMORY_SIGNING_KEY_PROVIDER"
	AWSKeySecretNameEnvVar    = "ARMORY_AWS_SIGNING_KEY"
	AWSKeyRegionEnvVar        = "ARMORY_AWS_REGION"
	VaultAddrEnvVar           = "ARMORY_VAULT_ADDR"
	VaultAppRolePathEnvVar    = "ARMORY_VAULT_APP_ROLE_PATH"
	VaultRoleIDEnvVar         = "ARMORY_VAULT_APP_ROLE_ID"
	VaultSecretIDEnvVar       = "ARMORY_VAULT_APP_SECRET_ID"
	VaultSigningKeyPathEnvVar = "ARMORY_VAULT_SIGNING_KEY_PATH"

	// Signing Key Providers
	SigningKeyProviderAWS   = "aws"
	SigningKeyProviderVault = "vault"
	SigningKeyProviderLocal = "local"

	// Signing Key Provider Details
	AWSSecretNameKey        = "secret-name"
	AWSRegionKey            = "region"
	VaultAddrKey            = "addr"
	VaultAppRolePathKey     = "app-role-path"
	VaultAppRoleIDKey       = "roleID"
	VaultAppSecretIDKey     = "secretID"
	VaultKeyPathKey         = "key-path"
	VaultCustomCAEnabledKey = "use-custom-ca"

	// Should not be edited directly, so hide them
	ArmoryIndexFileName    = ".armory-index.json"
	ArmoryIndexSigFileName = ".armory-index.minsig"
	SignaturesDirName      = ".armory-minisigs"
)
