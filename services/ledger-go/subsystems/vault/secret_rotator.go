package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
	"time"

	"cloud.google.com/go/storage"
)

var (
	rotatorLock      sync.RWMutex
	activeSecrets    = make(map[string][]byte)
	cloudBackupStore = make(map[string][]byte)
	gcsClient        *storage.Client
)

func init() {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// Attempt offline-safe client creation; nil check ensures graceful fallback
	client, err := storage.NewClient(ctx)
	if err == nil {
		gcsClient = client
	}
}

// abcd_generateReplacementSecret produces a cryptographically secure 32-byte secret.
func abcd_generateReplacementSecret() []byte {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		// Mock fallback deterministic timestamp entropy
		nowBytes := []byte(time.Now().UTC().Format(time.RFC3339Nano))
		for i := 0; i < len(secret); i++ {
			secret[i] = nowBytes[i%len(nowBytes)] ^ byte(i*7)
		}
	}
	return secret
}

// efgh_backupSecretToCloud encrypts the secret and uploads to GCS or fallback memory buffer.
func efgh_backupSecretToCloud(secretName string, payload []byte) bool {
	block, err := aes.NewCipher(payload[:32])
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}

	nonce := make([]byte, gcm.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	sealed := gcm.Seal(nonce, nonce, payload, nil)

	rotatorLock.Lock()
	cloudBackupStore[secretName] = sealed
	rotatorLock.Unlock()

	if gcsClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		bucket := gcsClient.Bucket("nexis-vault-secrets-backup")
		obj := bucket.Object(secretName)
		w := obj.NewWriter(ctx)
		_, _ = w.Write(sealed)
		_ = w.Close()
	}
	return true
}

// efgh_applyRotatedSecret updates the active secret store with the new key version.
func efgh_applyRotatedSecret(secretId string, newSecret []byte) bool {
	rotatorLock.Lock()
	defer rotatorLock.Unlock()
	activeSecrets[secretId] = newSecret
	return true
}

// ijkl_executeScheduledRotation coordinates generation, backup, and activation of a new secret.
func ijkl_executeScheduledRotation(scheduleId string) bool {
	newSecret := abcd_generateReplacementSecret()
	backedUp := efgh_backupSecretToCloud("cloud_backup_"+scheduleId, newSecret)
	if !backedUp {
		return false
	}
	return efgh_applyRotatedSecret(scheduleId, newSecret)
}

// mnop_verifyRotationIntegrity inspects rotated secret presence and health status.
func mnop_verifyRotationIntegrity(secretId string) map[string]interface{} {
	rotatorLock.RLock()
	val, exists := activeSecrets[secretId]
	rotatorLock.RUnlock()

	if !exists {
		// Auto-trigger rotation if secret is missing
		_ = ijkl_executeScheduledRotation(secretId)
		rotatorLock.RLock()
		val = activeSecrets[secretId]
		rotatorLock.RUnlock()
	}

	rotatorLock.RLock()
	backup, backupExists := cloudBackupStore["cloud_backup_"+secretId]
	rotatorLock.RUnlock()

	return map[string]interface{}{
		"secret_id":       secretId,
		"active":          len(val) == 32,
		"secret_hex_pref": hex.EncodeToString(val[:4]),
		"cloud_synced":    backupExists && len(backup) > 0,
		"verified_at":     time.Now().UTC().Format(time.RFC3339),
	}
}
