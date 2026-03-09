package filevalidation

import (
	"archive/zip"
	"bytes"
	"errors"
	"net/http"
)

var AllowedTypes = map[string]bool{
	"text/plain":      true,
	"image/jpeg":      true,
	"image/png":       true,
	"image/gif":       true,
	"image/webp":      true,
	"application/zip": true,
}

const MaxUncompressedSize = 500 * 1024 * 1024 // 500MB

func ValidateFileType(fileBytes []byte) error {
	contentType := http.DetectContentType(fileBytes)

	if !AllowedTypes[contentType] {
		return errors.New("file type not allowed: " + contentType)
	}

	// If the file is a ZIP, perform additional validation
	if contentType == "application/zip" {
		if err := ValidateZipBomb(fileBytes); err != nil {
			return err
		}
	}

	return nil
}

func ValidateZipBomb(data []byte) error {

	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return errors.New("invalid zip file")
	}

	var totalSize uint64

	for _, f := range r.File {
		totalSize += f.UncompressedSize64

		if totalSize > MaxUncompressedSize {
			return errors.New("zip expands too large")
		}
	}

	return nil
}
