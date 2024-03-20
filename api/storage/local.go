package storage

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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/sliverarmory/external-armory/api/patterns"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/sliverarmory/external-armory/util"
)

const (
	defaultDirectoryPermissions = os.FileMode(0770)
	defaultFilePermissions      = os.FileMode(0660)
)

type LocalStorageProvider struct {
	basePath            string
	initialized         bool
	paths               StoragePaths
	isNew               bool
	refreshEnabled      bool
	packageWatcher      *fsnotify.Watcher
	refreshEventChannel chan string
	refreshErrorChannel chan error
	refreshSetupErr     error
	loggers             []*os.File
	options             LocalStorageOptions
}

type LocalStorageOptions struct {
	BasePath string `json:"path"`
}

func checkAndCreateDirectory(name, path string, createAsNeeded bool) (bool, error) {
	pathInfo, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		if createAsNeeded {
			return true, os.Mkdir(path, defaultDirectoryPermissions)
		} else {
			return false, fmt.Errorf("path for %s (%q) does not exist, and the option to create directories as needed was not set", name, path)
		}
	}
	if !pathInfo.IsDir() {
		return false, fmt.Errorf("%q exists but is not a directory", path)
	}
	// Then the path exists and is a directory
	return false, nil
}

func (lsp *LocalStorageProvider) createDefaultBundleFile() error {
	_, err := os.Stat(lsp.paths.Bundles)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = os.WriteFile(lsp.paths.Bundles, []byte(`[]`), defaultFilePermissions)
			if err != nil {
				return fmt.Errorf("could not create default bundle file %q: %s", lsp.paths.Bundles, err)
			}
		} else {
			return fmt.Errorf("bundle file exists at %q, but could not get information on it: %s", lsp.paths.Bundles, err)
		}
	}
	return nil
}

func (lsp *LocalStorageProvider) setUpPackageWatcher() {
	/*
		This function does not return an error because an error in setting up the watcher is not fatal.
		Checking .AutoRefreshEnabled() after the provider is initialized will let other packages know
		if auto refresh is enabled, and they can set up a channel if they wish.
	*/
	var err error
	lsp.packageWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		lsp.refreshSetupErr = err
		lsp.refreshEnabled = false
		return
	}
	go func() {
		for {
			select {
			case event, ok := <-lsp.packageWatcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Write) {
					// A file event we are interested in has happened, so send the event down the channel
					lsp.refreshEventChannel <- fmt.Sprintf("%s: %s", event.Op.String(), event.Name)
				}
			case err, ok := <-lsp.packageWatcher.Errors:
				if !ok {
					return
				}
				lsp.refreshErrorChannel <- err
				lsp.refreshEnabled = false
			}
		}
	}()

	err = lsp.packageWatcher.Add(lsp.paths.Aliases)
	if err != nil {
		lsp.refreshSetupErr = err
		lsp.refreshEnabled = false
		lsp.packageWatcher.Close()
		return
	}

	err = lsp.packageWatcher.Add(lsp.paths.Extensions)
	if err != nil {
		lsp.refreshSetupErr = err
		lsp.refreshEnabled = false
		lsp.packageWatcher.Close()
		return
	}

	err = lsp.packageWatcher.Add(lsp.paths.Bundles)
	if err != nil {
		lsp.refreshSetupErr = err
		lsp.refreshEnabled = false
		lsp.packageWatcher.Close()
		return
	}
}

func (lsp *LocalStorageProvider) New(options StorageOptions, createAsNeeded, refreshEnabled bool) error {
	// Make sure the base path exists
	localOptions, ok := options.(LocalStorageOptions)
	if !ok {
		return errors.New("invalid options provided")
	}
	basePath := localOptions.BasePath
	pathInfo, err := os.Stat(basePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if !createAsNeeded {
				return fmt.Errorf("path %q does not exist, and the option to create directories as needed was not set", basePath)
			}
			err = os.Mkdir(basePath, defaultDirectoryPermissions)
			lsp.isNew = true
			if err != nil {
				return fmt.Errorf("could not create path %q: %s", basePath, err)
			}
		} else {
			return fmt.Errorf("could not get info on path %q: %s", basePath, err)
		}
	} else if !pathInfo.IsDir() {
		return fmt.Errorf("%q is not a directory. cannot continue", basePath)
	}

	// Check for or create the necessary directories
	// This is a map of a name for the directory to its path
	lsp.paths = StoragePaths{
		Aliases:           filepath.Join(basePath, consts.AliasesDirName),
		Extensions:        filepath.Join(basePath, consts.ExtensionsDirName),
		PackageSignatures: filepath.Join(basePath, consts.SignaturesDirName),
		Certificates:      filepath.Join(basePath, consts.CertificatesDirName),
		Bundles:           filepath.Join(basePath, consts.BundlesFileName),
		Logs:              filepath.Join(basePath, consts.LogDirName),
		Config:            filepath.Join(basePath, consts.ConfigFileName),
		Index:             filepath.Join(basePath, consts.ArmoryIndexFileName),
		IndexSignature:    filepath.Join(basePath, consts.ArmoryIndexSigFileName),
		PackageSigningKey: filepath.Join(basePath, consts.LocalSigningKeyName),
		CertificateKey:    filepath.Join(basePath, consts.TLSKeyPathFromRoot),
		CertificateCrt:    filepath.Join(basePath, consts.TLSCertPathFromRoot),
		VaultCAPEM:        filepath.Join(basePath, consts.VaultCAPathFromRoot),
	}

	var directoryCreated bool

	for directoryName, directoryPath := range lsp.paths.Directories() {
		directoryCreated, err = checkAndCreateDirectory(directoryName, directoryPath, createAsNeeded)
		if directoryCreated {
			lsp.isNew = true
		}
		if err != nil {
			return err
		}
	}

	// Create a default bundle file if one does not exist
	err = lsp.createDefaultBundleFile()
	if err != nil {
		return err
	}

	// We should have all of the directories we need, so we should be good to go
	lsp.basePath = basePath
	lsp.loggers = []*os.File{}
	lsp.options = localOptions
	lsp.initialized = true

	// Attempt to start package watcher / auto refresh
	if refreshEnabled {
		lsp.refreshSetupErr = nil
		lsp.refreshEventChannel = make(chan string)
		lsp.refreshErrorChannel = make(chan error)
		lsp.setUpPackageWatcher()
	} else {
		lsp.refreshEnabled = false
	}

	return nil
}

func (lsp *LocalStorageProvider) Name() string {
	return consts.LocalStorageProviderStr
}

func (lsp *LocalStorageProvider) Options() StorageOptions {
	return lsp.options
}

func (lsp *LocalStorageProvider) IsNew() bool {
	return lsp.isNew
}

func (lsp *LocalStorageProvider) Paths() (*StoragePaths, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return &lsp.paths, nil
}

func (lsp *LocalStorageProvider) AutoRefreshEnabled() (bool, error) {
	return lsp.refreshEnabled, lsp.refreshSetupErr
}

func (lsp *LocalStorageProvider) AutoRefreshChannels() (chan string, chan error, error) {
	if !lsp.initialized {
		return nil, nil, ErrStorageNotInitialized
	}

	if lsp.refreshSetupErr != nil {
		return nil, nil, lsp.refreshSetupErr
	}

	return lsp.refreshEventChannel, lsp.refreshErrorChannel, nil
}

func (lsp *LocalStorageProvider) Close() error {
	// Errors would only be generated when closing the log files in cases when the log file
	// was previously closed. We do not need to worry about that kind of error when tearing
	// down the provider.
	lsp.CloseLogging()
	lsp.initialized = false

	if lsp.refreshEnabled {
		return lsp.packageWatcher.Close()
	} else {
		return nil
	}
}

func (lsp *LocalStorageProvider) Destroy() error {
	lsp.packageWatcher.Close()
	// Errors would only be generated when closing the log files in cases when the log file
	// was previously closed. We do not need to worry about that kind of error when tearing
	// down the provider.
	lsp.CloseLogging()
	return os.RemoveAll(lsp.basePath)
}

func (lsp *LocalStorageProvider) readFile(path string) ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrDoesNotExist
		} else {
			return nil, err
		}
	}

	return data, nil
}

func (lsp *LocalStorageProvider) Initialized() bool {
	return lsp.initialized
}

func (lsp *LocalStorageProvider) BasePath() string {
	return lsp.basePath
}

func (lsp *LocalStorageProvider) CheckFile(fileName string) error {
	_, err := os.Stat(fileName)
	if errors.Is(err, os.ErrNotExist) {
		return ErrDoesNotExist
	}
	return err
}

func (lsp *LocalStorageProvider) SetConfigPath(newConfigPath string) error {
	fileInfo, err := os.Stat(newConfigPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%q is not a valid configuration path: %s", newConfigPath, err)
	}
	if err == nil && fileInfo.IsDir() {
		return fmt.Errorf("%q is a directory", newConfigPath)
	}

	lsp.paths.Config = newConfigPath
	return nil
}

func (lsp *LocalStorageProvider) ReadConfig() ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return lsp.readFile(lsp.paths.Config)
}

func (lsp *LocalStorageProvider) WriteConfig(configData []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	return os.WriteFile(lsp.paths.Config, configData, defaultFilePermissions)
}

func (lsp *LocalStorageProvider) ReadPackageSigningKey() ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return lsp.readFile(lsp.paths.PackageSigningKey)
}

func (lsp *LocalStorageProvider) WritePackageSigningKey(data []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	return os.WriteFile(lsp.paths.PackageSigningKey, data, defaultFilePermissions)
}

func (lsp *LocalStorageProvider) ReadTLSCertificateKey() ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return lsp.readFile(lsp.paths.CertificateKey)
}

func (lsp *LocalStorageProvider) WriteTLSCertificateKey(data []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	return os.WriteFile(lsp.paths.CertificateKey, data, defaultFilePermissions)
}

func (lsp *LocalStorageProvider) ReadTLSCertificateCrt() ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return lsp.readFile(lsp.paths.CertificateCrt)
}

func (lsp *LocalStorageProvider) WriteTLSCertificateCrt(data []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	return os.WriteFile(lsp.paths.CertificateCrt, data, defaultFilePermissions)
}

func (lsp *LocalStorageProvider) ReadBundleFile() ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return lsp.readFile(lsp.paths.Bundles)
}

func (lsp *LocalStorageProvider) WriteBundleFile(data []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	return os.WriteFile(lsp.paths.Bundles, data, defaultFilePermissions)
}

func (lsp *LocalStorageProvider) CheckPackage(packageName string) (consts.PackageType, error) {
	if !lsp.initialized {
		return consts.UnknownPackageType, ErrStorageNotInitialized
	}

	aliasPath := filepath.Join(lsp.paths.Aliases, fmt.Sprintf("%s.tar.gz", packageName))
	extensionPath := filepath.Join(lsp.paths.Extensions, fmt.Sprintf("%s.tar.gz", packageName))

	var packageType consts.PackageType

	_, err := os.Stat(aliasPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return consts.UnknownPackageType, err
		}
		_, err = os.Stat(extensionPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return consts.UnknownPackageType, ErrDoesNotExist
			} else {
				return consts.UnknownPackageType, err
			}
		} else {
			packageType = consts.ExtensionPackageType
		}
	} else {
		packageType = consts.AliasPackageType
	}
	return packageType, nil
}

func (lsp *LocalStorageProvider) ReadPackage(packageName string) ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	// We will try to read the package as an alias first. If that fails, we will try to read it as an extension.
	aliasPath := filepath.Join(lsp.paths.Aliases, fmt.Sprintf("%s.tar.gz", packageName))
	extensionPath := filepath.Join(lsp.paths.Extensions, fmt.Sprintf("%s.tar.gz", packageName))
	var packagePath string

	_, aliasErr := os.Stat(aliasPath)
	if aliasErr != nil {
		// Then try the extension
		_, extErr := os.Stat(extensionPath)
		if extErr != nil {
			if !errors.Is(extErr, os.ErrNotExist) {
				return nil, fmt.Errorf("could not get information for package %q: %s, %s", packageName, aliasErr, extErr)
			} else {
				if errors.Is(aliasErr, os.ErrNotExist) {
					return nil, fmt.Errorf("%q does not exist as either an alias or an extension", packageName)
				} else {
					return nil, fmt.Errorf("%q does not exist as an extension, and getting information about %q as an alias failed: %s",
						packageName, packageName, aliasErr)
				}
			}
		} else {
			packagePath = extensionPath
		}
	} else {
		packagePath = aliasPath
	}

	return os.ReadFile(packagePath)
}

func (lsp *LocalStorageProvider) WritePackage(packageName string, packageData []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	var packagePath string

	packageType := derivePackageTypeFromArchive(packageData)
	if packageType == consts.UnknownPackageType {
		return fmt.Errorf("could not write package %q: could not determine package type", packageName)
	}
	switch packageType {
	case consts.AliasPackageType:
		packagePath = filepath.Join(lsp.paths.Aliases, fmt.Sprintf("%s.tar.gz", packageName))
	case consts.ExtensionPackageType:
		packagePath = filepath.Join(lsp.paths.Extensions, fmt.Sprintf("%s.tar.gz", packageName))
	}

	return os.WriteFile(packagePath, packageData, defaultFilePermissions)
}

func (lsp *LocalStorageProvider) WritePackageWithFileName(fileName string, packageData []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	var packagePath string
	// Standardize the file name so that when we write to the filesystem, the filename will end with .tar.gz
	fileName = strings.TrimSuffix(fileName, ".tar.gz")

	packageType := derivePackageTypeFromArchive(packageData)
	if packageType == consts.UnknownPackageType {
		return errors.New("could not determine package type")
	}
	switch packageType {
	case consts.AliasPackageType:
		packagePath = filepath.Join(lsp.paths.Aliases, fmt.Sprintf("%s.tar.gz", fileName))
	case consts.ExtensionPackageType:
		packagePath = filepath.Join(lsp.paths.Extensions, fmt.Sprintf("%s.tar.gz", fileName))
	}

	return os.WriteFile(packagePath, packageData, defaultFilePermissions)
}

func (lsp *LocalStorageProvider) RemovePackage(packageName string) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	packageType, err := lsp.CheckPackage(packageName)
	if err != nil {
		return err
	}

	packagePath := ""
	switch packageType {
	case consts.AliasPackageType:
		packagePath = filepath.Join(lsp.paths.Aliases, fmt.Sprintf("%s.tar.gz", packageName))
	case consts.ExtensionPackageType:
		packagePath = filepath.Join(lsp.paths.Extensions, fmt.Sprintf("%s.tar.gz", packageName))
	default:
		return fmt.Errorf("the type of %s is not a supported package type", packageName)
	}

	return os.Remove(packagePath)
}

func (lsp *LocalStorageProvider) ListPackages(packageType consts.PackageType) (map[string]PackageEntry, []error) {
	if !lsp.initialized {
		return nil, []error{ErrStorageNotInitialized}
	}

	manifests := map[string]PackageEntry{}
	allErrors := []error{}
	entryDir := ""

	switch packageType {
	case consts.AliasPackageType:
		entryDir = lsp.paths.Aliases
	case consts.ExtensionPackageType:
		entryDir = lsp.paths.Extensions
	default:
		return manifests, []error{errors.New("unsupported package type")}
	}
	pathEntries, err := os.ReadDir(entryDir)
	if err != nil {
		return manifests, []error{fmt.Errorf("failed to read package directory: %s", err)}
	}

	for _, entry := range pathEntries {
		isV2Manifest := false
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		packagePath := filepath.Join(entryDir, entry.Name())
		switch packageType {
		case consts.AliasPackageType:
			manifestData, err := util.ReadFileFromTarGz(packagePath, consts.AliasArchiveManifestFilePath)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("could not read manifest from %s: %s", entry.Name(), err))
				continue
			}
			manifest := &patterns.AliasManifest{}
			err = json.Unmarshal(manifestData, manifest)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("could not parse manifest for %s: %s", entry.Name(), err))
				continue
			}
			if strings.TrimSuffix(entry.Name(), ".tar.gz") != manifest.CommandName {
				allErrors = append(allErrors, fmt.Errorf("invalid file name %q, expected %q", entry.Name(),
					fmt.Sprintf("%s.tar.gz", manifest.CommandName)))
				continue
			}
			manifests[manifest.Name] = PackageEntry{
				Name:         manifest.Name,
				CommandName:  manifest.CommandName,
				ManifestData: manifestData,
			}
		case consts.ExtensionPackageType:
			manifestData, err := util.ReadFileFromTarGz(packagePath, consts.ExtensionArchiveManifestFilePath)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("could not read manifest from %s: %s", entry.Name(), err))
				continue
			}
			manifest := &patterns.ExtensionManifestV1{}
			err = json.Unmarshal(manifestData, manifest)
			if err != nil {
				// Try a V2 manifest
				manifest := &patterns.ExtensionManifestV2{}
				err = json.Unmarshal(manifestData, manifest)
				if err != nil {
					allErrors = append(allErrors, fmt.Errorf("could not parse manifest for %s: %s", entry.Name(), err))
					continue
				}
				// Try to match a command name in the manifest with the base of the filename
				baseFileName := strings.TrimSuffix(entry.Name(), ".tar.gz")
				for _, cmd := range manifest.ExtCommand {
					if cmd.CommandName == baseFileName {
						manifest.CommandName = baseFileName
						break
					}
				}
				if manifest.CommandName == "" {
					allErrors = append(allErrors,
						fmt.Errorf("invalid file name %q, expected a file name that matches a command name provided by the extension", entry.Name()))
					continue
				}
				isV2Manifest = true
			}
			if !isV2Manifest && strings.TrimSuffix(entry.Name(), ".tar.gz") != manifest.CommandName {
				allErrors = append(allErrors, fmt.Errorf("invalid file name %q, expected %q", entry.Name(),
					fmt.Sprintf("%s.tar.gz", manifest.CommandName)))
				continue
			}
			manifests[manifest.CommandName] = PackageEntry{
				Name:         manifest.Name,
				CommandName:  manifest.CommandName,
				ManifestData: manifestData,
			}
		}
	}

	return manifests, allErrors
}

func (lsp *LocalStorageProvider) ReadPackageSignature(packageName string) ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}
	sigPath := filepath.Join(lsp.paths.PackageSignatures, packageName)
	return lsp.readFile(sigPath)
}

func (lsp *LocalStorageProvider) WritePackageSignature(packageName string, signatureData []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	sigPath := filepath.Join(lsp.paths.PackageSignatures, packageName)
	return os.WriteFile(sigPath, signatureData, defaultFilePermissions)
}

func (lsp *LocalStorageProvider) RemovePackageSignature(packageName string) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}
	sigPath := filepath.Join(lsp.paths.PackageSignatures, packageName)
	return os.Remove(sigPath)
}

func (lsp *LocalStorageProvider) ReadIndex() ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return lsp.readFile(lsp.paths.Index)
}

func (lsp *LocalStorageProvider) WriteIndex(indexData []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	return os.WriteFile(lsp.paths.Index, indexData, defaultFilePermissions)
}

func (lsp *LocalStorageProvider) ReadIndexSignature() ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return lsp.readFile(lsp.paths.IndexSignature)
}

func (lsp *LocalStorageProvider) WriteIndexSignature(indexSignatureData []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	return os.WriteFile(lsp.paths.IndexSignature, indexSignatureData, defaultFilePermissions)
}

func (lsp *LocalStorageProvider) GetLogger(logName string) (io.Writer, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	// Standardize the log name
	logName = strings.TrimSuffix(logName, ".log")

	logPath := filepath.Join(lsp.paths.Logs, fmt.Sprintf("%s.log", logName))

	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, defaultFilePermissions)
	if err != nil {
		return nil, err
	}

	lsp.loggers = append(lsp.loggers, logFile)

	return logFile, err
}

func (lsp *LocalStorageProvider) CloseLogging() []error {
	allErrors := []error{}

	return allErrors
}

func (lsp *LocalStorageProvider) ReadVaultCA() ([]byte, error) {
	if !lsp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return lsp.readFile(lsp.paths.VaultCAPEM)
}

func (lsp *LocalStorageProvider) WriteVaultCA(data []byte) error {
	if !lsp.initialized {
		return ErrStorageNotInitialized
	}

	return os.WriteFile(lsp.paths.VaultCAPEM, data, defaultFilePermissions)
}
