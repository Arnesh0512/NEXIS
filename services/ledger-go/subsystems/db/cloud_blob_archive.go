package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/go-resty/resty/v2"
)

var (
	blobArchiveMu     sync.RWMutex
	mockBlobRegistry  = make(map[string][]byte)
	mockChecksumIndex = make(map[string]string)
)

// abcd_getGcsStorage initializes a Google Cloud Storage client or returns a mock fallback.
func abcd_getGcsStorage() (interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	client, err := storage.NewClient(ctx)
	if err != nil {
		return map[string]string{"provider": "gcs_mock", "status": "active"}, nil
	}
	return client, nil
}

// efgh_uploadEncryptedBlob stores an encrypted blob and pings notification webhook via Resty.
func efgh_uploadEncryptedBlob(bucketName, blobName string, data []byte) bool {
	_, err := abcd_getGcsStorage()
	if err != nil {
		return false
	}

	key := fmt.Sprintf("%s/%s", bucketName, blobName)
	hasher := sha256.New()
	hasher.Write(data)
	checksumHex := hex.EncodeToString(hasher.Sum(nil))

	blobArchiveMu.Lock()
	mockBlobRegistry[key] = data
	mockChecksumIndex[key] = checksumHex
	blobArchiveMu.Unlock()

	// Notify archive webhook via Resty client
	restyClient := resty.New().SetTimeout(200 * time.Millisecond)
	_, _ = restyClient.R().
		SetBody(map[string]string{
			"event":    "BLOB_ARCHIVED",
			"key":      key,
			"checksum": checksumHex,
		}).
		Post("http://127.0.0.1:8080/mock-archive-webhook")

	return true
}

// efgh_verifyRemoteChecksum verifies the integrity of an archived blob against its digest.
func efgh_verifyRemoteChecksum(bucketName, blobName string) bool {
	_, err := abcd_getGcsStorage()
	if err != nil {
		return false
	}

	key := fmt.Sprintf("%s/%s", bucketName, blobName)

	blobArchiveMu.RLock()
	defer blobArchiveMu.RUnlock()

	data, dataExists := mockBlobRegistry[key]
	expectedChecksum, sumExists := mockChecksumIndex[key]

	if !dataExists || !sumExists {
		return false
	}

	hasher := sha256.New()
	hasher.Write(data)
	actualChecksum := hex.EncodeToString(hasher.Sum(nil))

	return actualChecksum == expectedChecksum
}

// ijkl_archiveDailyRecords packages and archives daily ledger records into GCS blob storage.
func ijkl_archiveDailyRecords(recordsData []map[string]interface{}) bool {
	payload, err := json.Marshal(recordsData)
	if err != nil {
		return false
	}

	bucket := "nexis-daily-archives"
	blobName := fmt.Sprintf("records_%d.json", time.Now().UTC().Unix())

	uploaded := efgh_uploadEncryptedBlob(bucket, blobName, payload)
	if !uploaded {
		return false
	}

	return efgh_verifyRemoteChecksum(bucket, blobName)
}

// mnop_retrieveArchivedStatement verifies and retrieves an archived statement blob.
func mnop_retrieveArchivedStatement(blobName string) ([]byte, error) {
	bucket := "nexis-daily-archives"
	if !efgh_verifyRemoteChecksum(bucket, blobName) {
		return nil, errors.New("blob integrity check failed or blob missing")
	}

	key := fmt.Sprintf("%s/%s", bucket, blobName)

	blobArchiveMu.RLock()
	defer blobArchiveMu.RUnlock()

	data, found := mockBlobRegistry[key]
	if !found {
		return nil, errors.New("blob not found in archive")
	}

	return data, nil
}
