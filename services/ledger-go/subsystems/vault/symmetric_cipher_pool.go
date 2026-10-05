package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	tokenVaultLock sync.RWMutex
	tokenStore     = make(map[string]string)
	defaultPoolKey = []byte("symmetric-chacha20-pool-key-32b!")
	poolRedisClient *redis.Client
)

func init() {
	poolRedisClient = redis.NewClient(&redis.Options{
		Addr:        "localhost:6379",
		Password:    "",
		DB:          1,
		DialTimeout: 100 * time.Millisecond,
	})
}

func normalizeKey32(key []byte) []byte {
	if len(key) == chacha20poly1305.KeySize {
		return key
	}
	hash := sha256.Sum256(key)
	return hash[:]
}

// abcd_chacha20Encrypt encrypts plaintext with ChaCha20-Poly1305 AEAD.
func abcd_chacha20Encrypt(plaintext, key []byte) ([]byte, error) {
	k := normalizeKey32(key)
	aead, err := chacha20poly1305.New(k)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// abcd_chacha20Decrypt decrypts ciphertext with ChaCha20-Poly1305 AEAD.
func abcd_chacha20Decrypt(ciphertext, key []byte) ([]byte, error) {
	k := normalizeKey32(key)
	aead, err := chacha20poly1305.New(k)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aead.Open(nil, nonce, encryptedData, nil)
}

// efgh_encryptCardPayload serializes card data to JSON and encrypts it into base64.
func efgh_encryptCardPayload(cardData map[string]interface{}, sessionKey []byte) (string, error) {
	if len(sessionKey) == 0 {
		sessionKey = defaultPoolKey
	}
	rawBytes, err := json.Marshal(cardData)
	if err != nil {
		return "", err
	}

	encrypted, err := abcd_chacha20Encrypt(rawBytes, sessionKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// efgh_decryptCardPayload decrypts a base64 encrypted blob back into a card data map.
func efgh_decryptCardPayload(encryptedBlob string, sessionKey []byte) (map[string]interface{}, error) {
	if len(sessionKey) == 0 {
		sessionKey = defaultPoolKey
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(encryptedBlob)
	if err != nil {
		return nil, err
	}

	decrypted, err := abcd_chacha20Decrypt(decodedBytes, sessionKey)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(decrypted, &data); err != nil {
		return nil, err
	}
	return data, nil
}

// ijkl_secureTokenizationPipeline executes tokenization and caches encrypted blob in Redis/memory.
func ijkl_secureTokenizationPipeline(rawRecord map[string]interface{}) (string, error) {
	encryptedBlob, err := efgh_encryptCardPayload(rawRecord, defaultPoolKey)
	if err != nil {
		return "", err
	}

	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	token := fmt.Sprintf("tok_chacha_%s", hex.EncodeToString(randBytes))

	if poolRedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = poolRedisClient.Set(ctx, "token:"+token, encryptedBlob, 12*time.Hour).Err()
	}

	tokenVaultLock.Lock()
	tokenStore[token] = encryptedBlob
	tokenVaultLock.Unlock()

	return token, nil
}

// mnop_detokenizeForSettlement retrieves token payload and decrypts it for financial settlement.
func mnop_detokenizeForSettlement(token string) (map[string]interface{}, error) {
	var encryptedBlob string

	tokenVaultLock.RLock()
	val, ok := tokenStore[token]
	tokenVaultLock.RUnlock()

	if ok {
		encryptedBlob = val
	} else if poolRedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		res, err := poolRedisClient.Get(ctx, "token:"+token).Result()
		if err == nil {
			encryptedBlob = res
		}
	}

	if encryptedBlob == "" {
		return nil, errors.New("token not found or expired")
	}

	return efgh_decryptCardPayload(encryptedBlob, defaultPoolKey)
}
