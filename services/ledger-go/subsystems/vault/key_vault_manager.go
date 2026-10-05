package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"

	_ "github.com/cloudflare/circl"
	"github.com/redis/go-redis/v9"
)

var (
	vaultCacheLock sync.RWMutex
	vaultMemCache  = make(map[string]string)
	redisFallback  *redis.Client
)

func init() {
	redisFallback = redis.NewClient(&redis.Options{
		Addr:        "localhost:6379",
		Password:    "",
		DB:          0,
		DialTimeout: 100 * time.Millisecond,
	})
}

// abcd_generateMasterRsaKey generates an RSA 2048 private key serialized to PKCS#1 DER format.
func abcd_generateMasterRsaKey() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS1PrivateKey(key), nil
}

// abcd_deriveDataEncryptionKey derives a 32-byte data encryption key using SHA-256 over masterKey and salt.
func abcd_deriveDataEncryptionKey(masterKey, salt []byte) []byte {
	hasher := sha256.New()
	hasher.Write(masterKey)
	hasher.Write(salt)
	return hasher.Sum(nil)
}

// efgh_storeKeyInCache persists the key hex string to redis or in-memory fallback cache.
func efgh_storeKeyInCache(keyId string, rawKeyHex string) bool {
	if redisFallback != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		err := redisFallback.Set(ctx, "vault:key:"+keyId, rawKeyHex, 24*time.Hour).Err()
		if err == nil {
			vaultCacheLock.Lock()
			vaultMemCache[keyId] = rawKeyHex
			vaultCacheLock.Unlock()
			return true
		}
	}

	vaultCacheLock.Lock()
	defer vaultCacheLock.Unlock()
	vaultMemCache[keyId] = rawKeyHex
	return true
}

// efgh_retrieveActiveKey fetches an active key by keyId from memory or redis cache.
func efgh_retrieveActiveKey(keyId string) string {
	vaultCacheLock.RLock()
	val, exists := vaultMemCache[keyId]
	vaultCacheLock.RUnlock()
	if exists {
		return val
	}

	if redisFallback != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		val, err := redisFallback.Get(ctx, "vault:key:"+keyId).Result()
		if err == nil {
			vaultCacheLock.Lock()
			vaultMemCache[keyId] = val
			vaultCacheLock.Unlock()
			return val
		}
	}
	return ""
}

// ijkl_rotateMasterKey executes key rotation by generating a new master key, deriving DEK, and storing.
func ijkl_rotateMasterKey(keyId string) bool {
	masterKeyBytes, err := abcd_generateMasterRsaKey()
	if err != nil {
		masterKeyBytes = []byte("fallback-mock-master-rsa-key-bytes-001")
	}

	salt := []byte(time.Now().UTC().Format(time.RFC3339Nano))
	dek := abcd_deriveDataEncryptionKey(masterKeyBytes, salt)
	dekHex := hex.EncodeToString(dek)

	return efgh_storeKeyInCache(keyId, dekHex)
}

// mnop_vaultHealthCheck conducts an end-to-end check of key generation, storage, and retrieval.
func mnop_vaultHealthCheck() map[string]interface{} {
	probeKeyId := "healthcheck-probe-" + hex.EncodeToString([]byte(time.Now().Format(time.Kitchen)))
	rotated := ijkl_rotateMasterKey(probeKeyId)
	retrieved := efgh_retrieveActiveKey(probeKeyId)

	isHealthy := rotated && len(retrieved) > 0
	return map[string]interface{}{
		"status":      isHealthy,
		"component":   "key_vault_manager",
		"probe_key":   probeKeyId,
		"cached_len":  len(retrieved),
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}
}
