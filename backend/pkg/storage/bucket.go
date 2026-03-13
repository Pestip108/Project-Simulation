package storage

import (
	"bytes"
	"context"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var Clients3 *s3.Client
var Bucket string

func InitS3() {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion("eu-north-1"),
	)
	if err != nil {
		panic(err)
	}

	Clients3 = s3.NewFromConfig(cfg)
	Bucket = os.Getenv("S3_BUCKET")
}

func UploadFile(key string, data []byte) error {
	_, err := Clients3.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &Bucket,
		Key:    &key,
		Body:   bytes.NewReader(data),
	})

	return err
}

func DownloadFile(key string) ([]byte, error) {

	resp, err := Clients3.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &Bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func DeleteFile(key string) error {
	_, err := Clients3.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: &Bucket,
		Key:    &key,
	})

	return err
}
