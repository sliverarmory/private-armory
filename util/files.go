package util

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// GzipBuf - Gzip a buffer
func GzipBuf(data []byte) []byte {
	var buf bytes.Buffer
	zip := gzip.NewWriter(&buf)
	zip.Write(data)
	zip.Close()
	return buf.Bytes()
}

// GunzipBuf - Gunzip a buffer
func GunzipBuf(data []byte) []byte {
	zip, _ := gzip.NewReader(bytes.NewBuffer(data))
	var buf bytes.Buffer
	buf.ReadFrom(zip)
	return buf.Bytes()
}

// ChmodR - Recursively chmod
func ChmodR(path string, filePerm, dirPerm os.FileMode) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			if info.IsDir() {
				err = os.Chmod(name, dirPerm)
			} else {
				err = os.Chmod(name, filePerm)
			}
		}
		return err
	})
}

// ByteCountBinary - Pretty print byte size
func ByteCountBinary(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ReadFileFromTarGz - Read a file from a tar.gz file in-memory
func ReadFileFromTarGzArchive(source io.Reader, tarPath string) ([]byte, error) {
	gzf, err := gzip.NewReader(source)
	if err != nil {
		return nil, err
	}
	defer gzf.Close()

	tarReader := tar.NewReader(gzf)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Name == tarPath {
			switch header.Typeflag {
			case tar.TypeDir: // = directory
				continue
			case tar.TypeReg: // = regular file
				return io.ReadAll(tarReader)
			}
		}
	}
	return nil, nil
}

func ReadFileFromTarGz(archivePath, tarPath string) ([]byte, error) {
	fileHandle, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer fileHandle.Close()
	return ReadFileFromTarGzArchive(fileHandle, tarPath)
}

func ReadFileFromTarGzMemory(archiveData []byte, tarPath string) ([]byte, error) {
	bytesReader := bytes.NewReader(archiveData)

	return ReadFileFromTarGzArchive(bytesReader, tarPath)
}

// Convenience function for copying a file
func CopyFile(srcPath, dstPath string) (err error) {
	inputFile, err := os.Open(srcPath)
	if err != nil {
		return
	}
	defer inputFile.Close()

	outputFile, err := os.Create(dstPath)
	if err != nil {
		return
	}
	// If there is some issue closing the destination, bubble that up
	defer func() {
		/*
			If there is another error waiting to be reported, then that error
			takes precedence. If there is no error waiting to be reported,
			then report the error from closing the file
		*/
		if closeErr := outputFile.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	_, err = io.Copy(outputFile, inputFile)
	return err
}
