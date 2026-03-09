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
	"application/pdf": true,
}

var dangerousKeywords = []string{
	"/JavaScript",
	"/OpenAction",
	"/Launch",
	"/EmbeddedFile",
}

const MaxUncompressedSize = 500 * 1024 * 1024 // 500MB

func ValidateFileType(fileBytes []byte) error {
	contentType := http.DetectContentType(fileBytes)

	if !AllowedTypes[contentType] {
		return errors.New("file type not allowed: " + contentType)
	}

	switch contentType {
	case "application/zip":
		if err := ValidateZipBomb(fileBytes); err != nil {
			return err
		}
	case "application/pdf":
		if err := ValidatePDF(fileBytes); err != nil {
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

func ValidatePDF(data []byte) error {
	if len(data) < 5 || string(data[:5]) != "%PDF-" {
		return errors.New("invalid PDF file")
	}

	for _, k := range dangerousKeywords {
		if bytes.Contains(data, []byte(k)) {
			return errors.New("PDF contains potentially dangerous content")
		}
	}

	return nil
}
