package filevalidation

import (
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

func ValidateFileType(fileBytes []byte) error {
	contentType := http.DetectContentType(fileBytes)

	if !AllowedTypes[contentType] {
		return errors.New("file type not allowed: " + contentType)
	}

	return nil
}
