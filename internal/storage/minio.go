package storage

import (
	"context"
	"bytes"
	"fmt"
	"os"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type minioStore struct {
	client *minio.Client
	bucket string
}

func newMinIOStore() ObjectStore {
	endpoint := os.Getenv("STORAGE_ENDPOINT")
	accessKey := os.Getenv("STORAGE_ACCESS_KEY")
	secretKey := os.Getenv("STORAGE_SECRET_KEY")
	bucket := os.Getenv("STORAGE_BUCKET")
	useSSL := os.Getenv("STORAGE_USE_SSL") == "true"

	if endpoint == "" || accessKey == "" || secretKey == "" || bucket == "" {
		return &noopStore{}
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return &noopStore{}
	}

	return &minioStore{client: client, bucket: bucket}
}

func (m *minioStore) Put(ctx context.Context, key string, data []byte, contentType string) error {
	if m == nil || m.client == nil {
		return nil
	}
	opts := minio.PutObjectOptions{ContentType: contentType}
	_, err := m.client.PutObject(ctx, m.bucket, key, bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		return fmt.Errorf("minio put %s: %w", key, err)
	}
	return nil
}

func (m *minioStore) Get(ctx context.Context, key string) ([]byte, error) {
	if m == nil || m.client == nil {
		return nil, nil
	}
	obj, err := m.client.GetObject(ctx, m.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("minio get %s: %w", key, err)
	}
	defer obj.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(obj); err != nil {
		return nil, fmt.Errorf("minio read %s: %w", key, err)
	}
	return buf.Bytes(), nil
}
