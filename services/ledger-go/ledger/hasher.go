package ledger

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// Hasher provides SHA-256 block hashing, Merkle tree node calculation,
// and HMAC-SHA256 message integrity verification for financial ledger journals.
type Hasher struct {
	secretKey     []byte
	hashCount     int64
	hmacCount     int64
	lock          sync.RWMutex
	cacheMap      map[string]string
	cacheCapacity int
}

// NewHasher initializes Hasher with a secret key for HMAC operations.
func NewHasher(hmacKey []byte) (*Hasher, error) {
	if len(hmacKey) < 16 {
		return nil, errors.New("HMAC secret key must be at least 16 bytes")
	}

	keyCopy := make([]byte, len(hmacKey))
	copy(keyCopy, hmacKey)

	return &Hasher{
		secretKey:     keyCopy,
		cacheMap:      make(map[string]string),
		cacheCapacity: 10000,
	}, nil
}

// ComputeSha256 calculates the SHA-256 digest of input bytes.
// Captured by Spectra rule: sha256.New (ALGO-SHA2-256)
func (h *Hasher) ComputeSha256(data []byte) string {
	h.lock.Lock()
	defer h.lock.Unlock()

	// Spectra detection target: sha256.New
	hasher := sha256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	h.hashCount++
	return hex.EncodeToString(digest)
}

// ComputeHmacSha256 calculates the HMAC-SHA256 authentication tag.
// Captured by Spectra rule: hmac.New (ALGO-HMAC)
func (h *Hasher) ComputeHmacSha256(message []byte) string {
	h.lock.Lock()
	defer h.lock.Unlock()

	// Spectra detection target: hmac.New
	mac := hmac.New(sha256.New, h.secretKey)
	mac.Write(message)
	tag := mac.Sum(nil)

	h.hmacCount++
	return hex.EncodeToString(tag)
}

// VerifyHmacSha256 validates an incoming hex-encoded HMAC tag in constant time.
func (h *Hasher) VerifyHmacSha256(message []byte, expectedHexTag string) bool {
	expectedBytes, err := hex.DecodeString(expectedHexTag)
	if err != nil {
		return false
	}

	h.lock.RLock()
	mac := hmac.New(sha256.New, h.secretKey)
	mac.Write(message)
	actualBytes := mac.Sum(nil)
	h.lock.RUnlock()

	// Constant-time check
	return subtle.ConstantTimeCompare(actualBytes, expectedBytes) == 1
}

// ComputeMerkleRoot computes the Merkle tree root for an ordered slice of transaction hashes.
func (h *Hasher) ComputeMerkleRoot(txHashes []string) (string, error) {
	if len(txHashes) == 0 {
		return "", errors.New("empty transaction hashes slice")
	}

	if len(txHashes) == 1 {
		return txHashes[0], nil
	}

	currentLevel := make([][]byte, len(txHashes))
	for i, hStr := range txHashes {
		b, err := hex.DecodeString(hStr)
		if err != nil {
			return "", fmt.Errorf("invalid hex hash at index %d: %w", i, err)
		}
		currentLevel[i] = b
	}

	for len(currentLevel) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				combined := append(currentLevel[i], currentLevel[i+1]...)
				h := sha256.Sum256(combined)
				nextLevel = append(nextLevel, h[:])
			} else {
				// Odd node duplicate
				combined := append(currentLevel[i], currentLevel[i]...)
				h := sha256.Sum256(combined)
				nextLevel = append(nextLevel, h[:])
			}
		}
		currentLevel = nextLevel
	}

	return hex.EncodeToString(currentLevel[0]), nil
}

// ComputeJournalHash hashes block header fields to generate block digest.
func (h *Hasher) ComputeJournalHash(index int64, prevHash string, merkleRoot string, timestamp int64) string {
	headerData := fmt.Sprintf("%d:%s:%s:%d", index, prevHash, merkleRoot, timestamp)
	return h.ComputeSha256([]byte(headerData))
}

// GetTelemetry returns operational telemetry metrics.
func (h *Hasher) GetTelemetry() map[string]interface{} {
	h.lock.RLock()
	defer h.lock.RUnlock()

	return map[string]interface{}{
		"sha256_computations": h.hashCount,
		"hmac_computations":   h.hmacCount,
		"cached_entries":      len(h.cacheMap),
	}
}
