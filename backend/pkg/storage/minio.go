package storage

import (
	"context"
	"log"
	"os"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var Client *minio.Client
var BucketName = "secretfiles"

func InitMinIO() {
	endpoint := os.Getenv("MINIO_ENDPOINT")
	accessKey := os.Getenv("MINIO_ROOT_USER")
	secretKey := os.Getenv("MINIO_ROOT_PASSWORD")
	useSSL := false

	var err error
	Client, err = minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		log.Fatalln(err)
	}

	ctx := context.Background()

	exists, err := Client.BucketExists(ctx, BucketName)
	if err != nil {
		log.Fatalln(err)
	}

	if !exists {
		err = Client.MakeBucket(ctx, BucketName, minio.MakeBucketOptions{})
		if err != nil {
			log.Fatalln(err)
		}
	}
}
