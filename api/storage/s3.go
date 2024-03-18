package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/sliverarmory/external-armory/api/patterns"
	"github.com/sliverarmory/external-armory/consts"
	"github.com/sliverarmory/external-armory/util"
)

type S3StorageProvider struct {
	baseBucket     string
	initialized    bool
	paths          StoragePaths
	isNew          bool
	refreshEnabled bool
	s3Client       *s3.Client
	options        S3StorageOptions
	loggers        map[string]*os.File
}

type S3StorageOptions struct {
	Region     string
	BucketName string
	Directory  string
}

func decodeError(err error) error {
	var s3APIError smithy.APIError

	if err == nil {
		return err
	}

	if errors.As(err, &s3APIError) {
		switch s3APIError.(type) {
		case *types.NotFound, *types.NoSuchKey, *types.NoSuchBucket:
			return ErrDoesNotExist

		default:
			fmt.Printf("I got error: %v\n", s3APIError)
			return err
		}
	} else {
		return fmt.Errorf("unknown error: %s", err)
	}
}

func (ssp *S3StorageProvider) createConfiguredBucket() error {
	var bucketConfig *types.CreateBucketConfiguration

	if ssp.options.Region != "" {
		bucketConfig = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(ssp.options.Region),
		}
	}

	_, err := ssp.s3Client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket:                    aws.String(ssp.options.BucketName),
		CreateBucketConfiguration: bucketConfig,
	})

	return err
}

func (ssp *S3StorageProvider) readObject(objectKey string) ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	result, err := ssp.s3Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(ssp.baseBucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return nil, decodeError(err)
	}

	return io.ReadAll(result.Body)
}

func (ssp *S3StorageProvider) writeObject(objectKey string, data []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	dataReader := bytes.NewReader(data)

	_, err := ssp.s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(ssp.baseBucket),
		Key:    aws.String(objectKey),
		Body:   dataReader,
	})

	return decodeError(err)
}

func (ssp *S3StorageProvider) deleteObject(objectKey string) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	_, err := ssp.s3Client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(ssp.baseBucket),
		Key:    aws.String(objectKey),
	})

	return decodeError(err)
}

func (ssp *S3StorageProvider) createDefaultBundleFile() error {
	// Check to see if there is a bundle file already
	err := ssp.CheckFile(ssp.paths.Bundles)
	if err != nil {
		if errors.Is(err, ErrDoesNotExist) {
			return ssp.writeObject(ssp.paths.Bundles, []byte(`[]`))
		} else {
			return decodeError(err)
		}
	}

	return nil
}

func (ssp *S3StorageProvider) listObjects(objectBasePath string) ([]string, error) {
	objectKeys := []string{}

	basePath := objectBasePath
	if basePath != "" && !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}

	objectListParameters := &s3.ListObjectsV2Input{
		Bucket: aws.String(ssp.baseBucket),
		Prefix: aws.String(basePath),
	}

	fullBucketPath := fmt.Sprintf("%s/%s", ssp.baseBucket, basePath)

	listResult, err := ssp.s3Client.ListObjectsV2(context.TODO(), objectListParameters)
	if err != nil {
		return nil, fmt.Errorf("could not list objects in %q: %s", fullBucketPath, err)
	}

	if *listResult.IsTruncated {
		for *listResult.IsTruncated {
			for _, entry := range listResult.Contents {
				objectKeys = append(objectKeys, *entry.Key)
			}
			objectListParameters.ContinuationToken = listResult.ContinuationToken
			listResult, err = ssp.s3Client.ListObjectsV2(context.TODO(), objectListParameters)
			if err != nil {
				return nil, err
			}
		}
	}

	for _, entry := range listResult.Contents {
		objectKeys = append(objectKeys, *entry.Key)
	}

	return objectKeys, nil
}

func (ssp *S3StorageProvider) New(options StorageOptions, createAsNeeded bool) error {
	s3Options, ok := options.(S3StorageOptions)
	if !ok {
		return errors.New("invalid options provided")
	}

	s3Config, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("could not load S3 config: %s", err)
	}

	if s3Options.Region != "" {
		s3Config.Region = s3Options.Region
	} else {
		return errors.New("S3 region not specified")
	}

	ssp.s3Client = s3.NewFromConfig(s3Config)

	// Check if the bucket exists
	_, err = ssp.s3Client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
		Bucket: aws.String(s3Options.BucketName),
	})
	if err != nil {
		// Check to see if the bucket was not found (if that was the error, we can try to create it)
		var s3APIError smithy.APIError
		if errors.As(err, &s3APIError) {
			switch s3APIError.(type) {
			case *types.NotFound:
				createErr := ssp.createConfiguredBucket()
				if createErr != nil {
					if ssp.options.Region != "" {
						return fmt.Errorf("error creating bucket %q in region %s: %s", s3Options.BucketName, s3Options.Region, err)
					} else {
						return fmt.Errorf("error creating bucket %q: %s", s3Options.BucketName, err)
					}
				}
			default:
				return fmt.Errorf("error checking for bucket %q: %s", s3Options.BucketName, err)
			}
		} else {
			return fmt.Errorf("unknown error: %s", err)
		}
	}

	// If we are here, then the bucket exists
	// Create the paths
	bucketDirectory := s3Options.Directory
	if bucketDirectory != "" && !strings.HasSuffix(bucketDirectory, "/") {
		bucketDirectory = bucketDirectory + "/"
		s3Options.Directory = bucketDirectory
	}

	// Given how S3 works, all paths are relative to the bucket. The application assumes all files are stored in one bucket.
	ssp.paths = StoragePaths{
		Aliases:           fmt.Sprintf("%s%s/", bucketDirectory, consts.AliasesDirName),
		Extensions:        fmt.Sprintf("%s%s/", bucketDirectory, consts.ExtensionsDirName),
		PackageSignatures: fmt.Sprintf("%s%s/", bucketDirectory, consts.SignaturesDirName),
		Certificates:      fmt.Sprintf("%s%s/", bucketDirectory, consts.CertificatesDirName),
		Logs:              fmt.Sprintf("%s%s/", bucketDirectory, consts.LogDirName),
		Bundles:           fmt.Sprintf("%s%s", bucketDirectory, consts.BundlesFileName),
		Config:            fmt.Sprintf("%s%s", bucketDirectory, consts.ConfigFileName),
		Index:             fmt.Sprintf("%s%s", bucketDirectory, consts.ArmoryIndexFileName),
		IndexSignature:    fmt.Sprintf("%s%s", bucketDirectory, consts.ArmoryIndexSigFileName),
		PackageSigningKey: fmt.Sprintf("%s%s", bucketDirectory, consts.LocalSigningKeyName),
		CertificateKey:    fmt.Sprintf("%s%s/%s", bucketDirectory, consts.CertificatesDirName, consts.TLSKeyFileName),
		CertificateCrt:    fmt.Sprintf("%s%s/%s", bucketDirectory, consts.CertificatesDirName, consts.TLSCertFileName),
		VaultCAPEM:        fmt.Sprintf("%s%s/%s", bucketDirectory, consts.CertificatesDirName, consts.VaultCAFileName),
	}

	ssp.options = s3Options
	ssp.baseBucket = ssp.options.BucketName
	// Have to log locally because objects in S3 are immutable
	ssp.loggers = map[string]*os.File{}
	ssp.refreshEnabled = false
	ssp.initialized = true

	// If there is no config file, assume the armory is new
	err = ssp.CheckFile(ssp.paths.Config)
	if err != nil {
		if errors.Is(err, ErrDoesNotExist) {
			ssp.isNew = true
		} else {
			ssp.initialized = false
			return fmt.Errorf("could not check for config file: %s", err)
		}
	} else {
		ssp.isNew = false
	}

	// Create a default bundle file if one does not exist
	err = ssp.createDefaultBundleFile()
	if err != nil {
		ssp.initialized = false
		return fmt.Errorf("error creating default bundle file: %s", err)
	}
	return nil
}

func (ssp *S3StorageProvider) Name() string {
	return consts.AWSS3StorageProviderStr
}

func (ssp *S3StorageProvider) Options() StorageOptions {
	return ssp.options
}

func (ssp *S3StorageProvider) IsNew() bool {
	return ssp.isNew
}

func (ssp *S3StorageProvider) Paths() (*StoragePaths, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return &ssp.paths, nil
}

func (ssp *S3StorageProvider) AutoRefreshEnabled() (bool, error) {
	return ssp.refreshEnabled, nil
}

func (ssp *S3StorageProvider) AutoRefreshChannels() (chan string, chan error, error) {
	return nil, nil, nil
}

func (ssp *S3StorageProvider) Close() error {
	// Errors would only be generated when closing the log files in cases when the log file
	// was previously closed. We do not need to worry about that kind of error when tearing
	// down the provider.
	ssp.CloseLogger()

	// The S3 client does not have a close function
	return nil
}

// This function does not delete the bucket itself, just the armory objects inside of it
func (ssp *S3StorageProvider) Destroy() error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	// Close logger files if there any
	for _, logger := range ssp.loggers {
		// Errors are only generated from Close() if the file was closed previously, and
		// we do not need to worry about that kind of error when tearing down the provider
		logger.Close()
	}

	var objectIds []types.ObjectIdentifier
	for _, objectKey := range ssp.paths.Files() {
		objectIds = append(objectIds, types.ObjectIdentifier{Key: aws.String(objectKey)})
	}
	// Need to get the paths for aliases, extensions, and package signatures
	aliases, err := ssp.listObjects(ssp.paths.Aliases)
	if err != nil {
		return fmt.Errorf("could not list aliases: %s", err)
	}

	for _, aliasKey := range aliases {
		objectIds = append(objectIds, types.ObjectIdentifier{Key: aws.String(aliasKey)})
	}

	extensions, err := ssp.listObjects(ssp.paths.Extensions)
	if err != nil {
		return fmt.Errorf("could not list extensions: %s", err)
	}

	for _, extKey := range extensions {
		objectIds = append(objectIds, types.ObjectIdentifier{Key: aws.String(extKey)})
	}

	signatures, err := ssp.listObjects(ssp.paths.PackageSignatures)
	if err != nil {
		return fmt.Errorf("could not list package signatures: %s", err)
	}

	for _, signatureKey := range signatures {
		objectIds = append(objectIds, types.ObjectIdentifier{Key: aws.String(signatureKey)})
	}

	_, err = ssp.s3Client.DeleteObjects(context.TODO(), &s3.DeleteObjectsInput{
		Bucket: aws.String(ssp.baseBucket),
		Delete: &types.Delete{Objects: objectIds},
	})

	if err != nil {
		return fmt.Errorf("error deleting objects from bucket %q: %s", ssp.baseBucket, err)
	}

	return nil
}

func (ssp *S3StorageProvider) Initialized() bool {
	return ssp.initialized
}

func (ssp *S3StorageProvider) BasePath() string {
	return fmt.Sprintf("s3://%s", ssp.baseBucket)
}

func (ssp *S3StorageProvider) CheckFile(objectKey string) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	_, err := ssp.s3Client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(ssp.options.BucketName),
		Key:    aws.String(objectKey),
	})

	return decodeError(err)
}

func (ssp *S3StorageProvider) SetConfigPath(newConfigPath string) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	newConfigPath = strings.TrimPrefix(newConfigPath, "/")
	// Check that new path is valid
	err := ssp.CheckFile(newConfigPath)
	if err != nil {
		// If the path points to an object that does not exist, that is okay.
		if !errors.Is(err, ErrDoesNotExist) {
			return fmt.Errorf("invalid path %q: %s", newConfigPath, err)
		}
	}
	ssp.paths.Config = newConfigPath
	return nil
}

func (ssp *S3StorageProvider) ReadConfig() ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return ssp.readObject(ssp.paths.Config)
}

func (ssp *S3StorageProvider) WriteConfig(configData []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	return ssp.writeObject(ssp.paths.Config, configData)
}

func (ssp *S3StorageProvider) ReadPackageSigningKey() ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return ssp.readObject(ssp.paths.PackageSigningKey)
}

func (ssp *S3StorageProvider) WritePackageSigningKey(data []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	return ssp.writeObject(ssp.paths.PackageSigningKey, data)
}

func (ssp *S3StorageProvider) ReadTLSCertificateKey() ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return ssp.readObject(ssp.paths.CertificateKey)
}

func (ssp *S3StorageProvider) WriteTLSCertificateKey(data []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	return ssp.writeObject(ssp.paths.CertificateKey, data)
}

func (ssp *S3StorageProvider) ReadTLSCertificateCrt() ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return ssp.readObject(ssp.paths.CertificateCrt)
}

func (ssp *S3StorageProvider) WriteTLSCertificateCrt(data []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	return ssp.writeObject(ssp.paths.CertificateCrt, data)
}

func (ssp *S3StorageProvider) ReadBundleFile() ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return ssp.readObject(ssp.paths.Bundles)
}

func (ssp *S3StorageProvider) WriteBundleFile(data []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	return ssp.writeObject(ssp.paths.Bundles, data)
}

func (ssp *S3StorageProvider) CheckPackage(packageName string) (consts.PackageType, error) {
	if !ssp.initialized {
		return consts.UnknownPackageType, ErrStorageNotInitialized
	}

	aliasPath := fmt.Sprintf("%s%s.tar.gz", ssp.paths.Aliases, packageName)
	extensionPath := fmt.Sprintf("%s%s.tar.gz", ssp.paths.Extensions, packageName)

	var packageType consts.PackageType

	aliasErr := ssp.CheckFile(aliasPath)
	if aliasErr != nil {
		if errors.Is(aliasErr, ErrDoesNotExist) {
			// Not an alias, let's try an extension
			extErr := ssp.CheckFile(extensionPath)
			if extErr != nil {
				return consts.UnknownPackageType, extErr
			} else {
				packageType = consts.ExtensionPackageType
			}
		} else {
			return consts.UnknownPackageType, aliasErr
		}
	} else {
		packageType = consts.AliasPackageType
	}

	return packageType, nil
}

func (ssp *S3StorageProvider) ReadPackage(packageName string) ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	var packagePath string

	packageType, err := ssp.CheckPackage(packageName)
	if err != nil {
		return nil, err
	}

	switch packageType {
	case consts.AliasPackageType:
		packagePath = fmt.Sprintf("%s%s.tar.gz", ssp.paths.Aliases, packageName)
	case consts.ExtensionPackageType:
		packagePath = fmt.Sprintf("%s%s.tar.gz", ssp.paths.Extensions, packageName)
	default:
		return nil, fmt.Errorf("%q has an unsupported package type", packageName)
	}

	return ssp.readObject(packagePath)
}

func (ssp *S3StorageProvider) WritePackage(packageName string, packageData []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	var packagePath string

	packageType := derivePackageTypeFromArchive(packageData)
	if packageType == consts.UnknownPackageType {
		return fmt.Errorf("could not storage package %q: could not determine package type", packageName)
	}

	switch packageType {
	case consts.AliasPackageType:
		packagePath = fmt.Sprintf("%s%s.tar.gz", ssp.paths.Aliases, packageName)
	case consts.ExtensionPackageType:
		packagePath = fmt.Sprintf("%s%s.tar.gz", ssp.paths.Extensions, packageName)
	}

	return ssp.writeObject(packagePath, packageData)
}

func (ssp *S3StorageProvider) WritePackageWithFileName(fileName string, packageData []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	fileName = strings.TrimSuffix(fileName, ".tar.gz")

	var packagePath string

	packageType := derivePackageTypeFromArchive(packageData)
	if packageType == consts.UnknownPackageType {
		return fmt.Errorf("could not storage package %q: could not determine package type", fileName)
	}

	switch packageType {
	case consts.AliasPackageType:
		packagePath = fmt.Sprintf("%s%s.tar.gz", ssp.paths.Aliases, fileName)
	case consts.ExtensionPackageType:
		packagePath = fmt.Sprintf("%s%s.tar.gz", ssp.paths.Extensions, fileName)
	}

	return ssp.writeObject(packagePath, packageData)
}

func (ssp *S3StorageProvider) RemovePackage(packageName string) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	packageType, err := ssp.CheckPackage(packageName)
	if err != nil {
		return err
	}

	var packagePath string

	switch packageType {
	case consts.AliasPackageType:
		packagePath = fmt.Sprintf("%s%s.tar.gz", ssp.paths.Aliases, packageName)
	case consts.ExtensionPackageType:
		packagePath = fmt.Sprintf("%s%s.tar.gz", ssp.paths.Extensions, packageName)
	default:
		return fmt.Errorf("%q has an unsupported package type", packageName)
	}

	return ssp.deleteObject(packagePath)
}

func (ssp *S3StorageProvider) ListPackages(packageType consts.PackageType) (map[string]PackageEntry, []error) {
	if !ssp.initialized {
		return nil, []error{ErrStorageNotInitialized}
	}

	manifests := map[string]PackageEntry{}
	allErrors := []error{}

	var objectPaths []string
	var err error

	switch packageType {
	case consts.AliasPackageType:
		objectPaths, err = ssp.listObjects(ssp.paths.Aliases)
	case consts.ExtensionPackageType:
		objectPaths, err = ssp.listObjects(ssp.paths.Extensions)
	default:
		return nil, []error{errors.New("unsupported package type")}
	}

	if err != nil {
		return nil, []error{err}
	}

	for _, entry := range objectPaths {
		isV2Manifest := false
		if !strings.HasSuffix(entry, ".tar.gz") {
			continue
		}
		objectData, err := ssp.readObject(entry)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("could not read object %s: %s", entry, err))
			continue
		}
		switch packageType {
		case consts.AliasPackageType:
			manifestData, err := util.ReadFileFromTarGzMemory(objectData, consts.AliasArchiveManifestFilePath)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("could not read manifest from %s: %s", entry, err))
				continue
			}
			manifest := &patterns.AliasManifest{}
			err = json.Unmarshal(manifestData, manifest)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("could not parse manifest for %s: %s", entry, err))
				continue
			}
			if strings.TrimSuffix(entry, ".tar.gz") != manifest.CommandName {
				allErrors = append(allErrors, fmt.Errorf("invalid file name %q, expected %q", entry, fmt.Sprintf("%s.tar.gz", manifest.CommandName)))
				continue
			}
			manifests[manifest.Name] = PackageEntry{
				Name:         manifest.Name,
				CommandName:  manifest.CommandName,
				ManifestData: manifestData,
			}
		case consts.ExtensionPackageType:
			baseName := strings.TrimSuffix(filepath.Base(entry), ".tar.gz")
			manifestData, err := util.ReadFileFromTarGzMemory(objectData, consts.ExtensionArchiveManifestFilePath)
			if err != nil {
				allErrors = append(allErrors, fmt.Errorf("could not read manifest from %s: %s", entry, err))
				continue
			}
			manifest := &patterns.ExtensionManifestV1{}
			err = json.Unmarshal(manifestData, manifest)
			if err != nil {
				// Try a V2 manifest
				manifest := &patterns.ExtensionManifestV2{}
				err = json.Unmarshal(objectData, manifest)
				if err != nil {
					allErrors = append(allErrors, fmt.Errorf("could not parse manifest for %s: %s", entry, err))
					continue
				}
				// Try to match a command name in the manifest with the base of the filename
				for _, cmd := range manifest.ExtCommand {
					if cmd.CommandName == baseName {
						manifest.CommandName = baseName
						break
					}
				}
				if manifest.CommandName == "" {
					allErrors = append(allErrors,
						fmt.Errorf("invalid file name %q, expected a file name that matches a command name provided by the extension", entry))
					continue
				}
				isV2Manifest = true
			}
			if !isV2Manifest && baseName != manifest.CommandName {
				allErrors = append(allErrors, fmt.Errorf("invalid file name %q, expected %q", entry, fmt.Sprintf("%s.tar.gz", manifest.CommandName)))
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

func (ssp *S3StorageProvider) ReadPackageSignature(packageName string) ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	signaturePath := fmt.Sprintf("%s%s", ssp.paths.PackageSignatures, packageName)
	return ssp.readObject(signaturePath)
}

func (ssp *S3StorageProvider) WritePackageSignature(packageName string, signatureData []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	signaturePath := fmt.Sprintf("%s%s", ssp.paths.PackageSignatures, packageName)
	return ssp.writeObject(signaturePath, signatureData)
}

func (ssp *S3StorageProvider) RemovePackageSignature(packageName string) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	signaturePath := fmt.Sprintf("%s%s", ssp.paths.PackageSignatures, packageName)
	return ssp.deleteObject(signaturePath)
}

func (ssp *S3StorageProvider) ReadIndex() ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return ssp.readObject(ssp.paths.Index)
}

func (ssp *S3StorageProvider) WriteIndex(indexData []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	return ssp.writeObject(ssp.paths.Index, indexData)
}

func (ssp *S3StorageProvider) ReadIndexSignature() ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return ssp.readObject(ssp.paths.IndexSignature)
}

func (ssp *S3StorageProvider) WriteIndexSignature(indexSignatureData []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	return ssp.writeObject(ssp.paths.IndexSignature, indexSignatureData)
}

func (ssp *S3StorageProvider) GetLogger(logName string) (io.Writer, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	// Objects in S3 are immutable, so we cannot return a handle to an object that the logger
	// would continuously update. Instead, we will make a temp file locally that gets
	// uploaded once it is closed
	// Blank string for the first argument means the OS temp directory
	logFile, err := os.CreateTemp("", "armory-logger-*")
	if err != nil {
		return nil, err
	}

	logName = fmt.Sprintf("%s.log", strings.TrimSuffix(logName, ".log"))

	ssp.loggers[logName] = logFile

	return logFile, err
}

func (ssp *S3StorageProvider) CloseLogger() []error {
	if !ssp.initialized {
		return []error{ErrStorageNotInitialized}
	}

	allErrors := []error{}
	successfullyClosed := []string{}

	// Upload log files to S3, remove them from the filesystem upon success
	for logName, logFile := range ssp.loggers {
		logPathLocal := logFile.Name()
		logPathBucket := fmt.Sprintf("%s%s", ssp.paths.Logs, logName)

		logData, err := os.ReadFile(logPathLocal)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("could not read data from log file %q - make sure to recover the log data: %s", logPathLocal, err))
			continue
		}

		// Check to see if there is already a log file with logName in the bucket
		err = ssp.CheckFile(logPathBucket)
		if err != nil {
			if !errors.Is(err, ErrDoesNotExist) {
				allErrors = append(allErrors, fmt.Errorf("error checking log in bucket %q - make sure to recover the log data (%s): %s", logPathBucket, logPathLocal, err))
				continue
			}
		} else {
			// The log exists, so we need to pull the content so we can append the new content to it
			existingLogData, err := ssp.readObject(logPathBucket)
			if err != nil {
				logPathBucketNew := fmt.Sprintf("%s%s-%s.log", ssp.paths.Logs, strings.TrimSuffix(logName, ".log"), time.Now().Format("20060102_150405"))
				allErrors = append(allErrors,
					fmt.Errorf("could not get existing log data from S3 (%s) - will try to save log to %s: %s", logPathBucket, logPathBucketNew, err),
				)
				logPathBucket = logPathBucketNew
			}
			logData = append(existingLogData, logData...)
		}
		// We should be ready to upload the log to S3
		err = ssp.writeObject(logPathBucket, logData)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("could not write log data to S3 (%s) - make sure to recover the log data (%s): %s", logPathBucket, logPathLocal, err))
			continue
		}
		// Remove the local copy
		err = os.Remove(logPathLocal)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("could not remove temporary log %s - it needs to removed manually: %s", logPathLocal, err))
		}
		// Mark the log as successully closed even if we could not remove the local copy. We are not going to re-upload the log data at this point
		// since it is already in S3
		successfullyClosed = append(successfullyClosed, logName)
	}

	// Remove closed loggers from the loggers we are tracking in case this function is called again
	for _, name := range successfullyClosed {
		delete(ssp.loggers, name)
	}

	return allErrors
}

func (ssp *S3StorageProvider) ReadVaultCA() ([]byte, error) {
	if !ssp.initialized {
		return nil, ErrStorageNotInitialized
	}

	return ssp.readObject(ssp.paths.VaultCAPEM)
}

func (ssp *S3StorageProvider) WriteVaultCA(data []byte) error {
	if !ssp.initialized {
		return ErrStorageNotInitialized
	}

	return ssp.writeObject(ssp.paths.VaultCAPEM, data)
}
