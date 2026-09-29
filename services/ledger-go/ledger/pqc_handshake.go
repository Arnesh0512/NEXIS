package ledger

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// PqcHandshakeManager orchestrates post-quantum key encapsulation using Kyber768 (ML-KEM-768)
// to establish quantum-resistant symmetric session secrets between financial ledger nodes.
type PqcHandshakeManager struct {
	keyStore           map[string]*kyber768.PrivateKey
	publicKeyStore     map[string]*kyber768.PublicKey
	establishedSecrets map[string][]byte
	mutex              sync.RWMutex
	handshakesTotal    int64
	encapsulationsMade int64
	decapsulationsMade int64
}

// NewPqcHandshakeManager creates a new Post-Quantum KEM manager.
func NewPqcHandshakeManager() *PqcHandshakeManager {
	return &PqcHandshakeManager{
		keyStore:           make(map[string]*kyber768.PrivateKey),
		publicKeyStore:     make(map[string]*kyber768.PublicKey),
		establishedSecrets: make(map[string][]byte),
	}
}

// GenerateNodeKeyPair generates a Kyber768 post-quantum keypair.
// Captured by Spectra rule: kyber768.GenerateKeyPair (ALGO-ML-KEM)
func (pqc *PqcHandshakeManager) GenerateNodeKeyPair(nodeID string) (*kyber768.PublicKey, error) {
	if nodeID == "" {
		return nil, errors.New("node ID cannot be empty")
	}

	pqc.mutex.Lock()
	defer pqc.mutex.Unlock()

	// Spectra detection target: kyber768.GenerateKeyPair
	pk, sk, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("kyber768.GenerateKeyPair failed: %w", err)
	}

	pqc.keyStore[nodeID] = sk
	pqc.publicKeyStore[nodeID] = pk
	pqc.handshakesTotal++

	return pk, nil
}

// EncapsulateSecret encaps-processes a shared secret against a remote peer's Kyber768 public key.
func (pqc *PqcHandshakeManager) EncapsulateSecret(peerID string, peerPubKey *kyber768.PublicKey) (ciphertext []byte, sharedSecret []byte, err error) {
	if peerPubKey == nil {
		return nil, nil, errors.New("peer public key cannot be nil")
	}

	pqc.mutex.Lock()
	defer pqc.mutex.Unlock()

	ct := make([]byte, kyber768.CiphertextSize)
	ss := make([]byte, kyber768.SharedKeySize)

	// Encapsulate generates ciphertext and shared secret
	peerPubKey.EncapsulateTo(ct, ss, rand.Reader)
	pqc.establishedSecrets[peerID] = ss
	pqc.encapsulationsMade++

	return ct, ss, nil
}

// DecapsulateSecret decapsulates received Kyber768 ciphertext using local node's private key.
func (pqc *PqcHandshakeManager) DecapsulateSecret(nodeID, peerID string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != kyber768.CiphertextSize {
		return nil, fmt.Errorf("invalid Kyber768 ciphertext length: expected %d, got %d", kyber768.CiphertextSize, len(ciphertext))
	}

	pqc.mutex.Lock()
	defer pqc.mutex.Unlock()

	sk, ok := pqc.keyStore[nodeID]
	if !ok {
		return nil, fmt.Errorf("private key not found for node: %s", nodeID)
	}

	ss := make([]byte, kyber768.SharedKeySize)
	sk.DecapsulateTo(ss, ciphertext)

	pqc.establishedSecrets[peerID] = ss
	pqc.decapsulationsMade++

	return ss, nil
}

// GetEstablishedSecret retrieves the derived quantum-safe symmetric secret for a peer.
func (pqc *PqcHandshakeManager) GetEstablishedSecret(peerID string) ([]byte, bool) {
	pqc.mutex.RLock()
	defer pqc.mutex.RUnlock()

	secret, ok := pqc.establishedSecrets[peerID]
	if !ok {
		return nil, false
	}
	// Return copy
	cpy := make([]byte, len(secret))
	copy(cpy, secret)
	return cpy, true
}

// ExportPublicKeyHex exports the serialized public key bytes as hex string.
func (pqc *PqcHandshakeManager) ExportPublicKeyHex(nodeID string) (string, error) {
	pqc.mutex.RLock()
	defer pqc.mutex.RUnlock()

	pk, ok := pqc.publicKeyStore[nodeID]
	if !ok {
		return "", fmt.Errorf("public key not found for node: %s", nodeID)
	}

	var buf [kyber768.PublicKeySize]byte
	pk.Pack(&buf)
	return hex.EncodeToString(buf[:]), nil
}

// ImportPublicKeyHex deserializes a Kyber768 public key from hex.
func (pqc *PqcHandshakeManager) ImportPublicKeyHex(nodeID, hexStr string) (*kyber768.PublicKey, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex decode failed: %w", err)
	}
	if len(bytes) != kyber768.PublicKeySize {
		return nil, fmt.Errorf("invalid byte size for Kyber768 public key: %d", len(bytes))
	}

	var buf [kyber768.PublicKeySize]byte
	copy(buf[:], bytes)

	pk := new(kyber768.PublicKey)
	pk.Unpack(&buf)

	pqc.mutex.Lock()
	pqc.publicKeyStore[nodeID] = pk
	pqc.mutex.Unlock()

	return pk, nil
}

// ClearSessionSecret removes a session key upon peer disconnection.
func (pqc *PqcHandshakeManager) ClearSessionSecret(peerID string) {
	pqc.mutex.Lock()
	defer pqc.mutex.Unlock()

	if sec, ok := pqc.establishedSecrets[peerID]; ok {
		for i := range sec {
			sec[i] = 0 // Zeroize memory
		}
		delete(pqc.establishedSecrets, peerID)
	}
}

// GetTelemetry returns runtime statistics for post-quantum handshake operations.
func (pqc *PqcHandshakeManager) GetTelemetry() map[string]interface{} {
	pqc.mutex.RLock()
	defer pqc.mutex.RUnlock()

	return map[string]interface{}{
		"algorithm":           "ML-KEM-768",
		"quantum_safe":        true,
		"handshakes_total":    pqc.handshakesTotal,
		"encapsulations_made": pqc.encapsulationsMade,
		"decapsulations_made": pqc.decapsulationsMade,
		"active_secrets":      len(pqc.establishedSecrets),
		"stored_keypairs":     len(pqc.keyStore),
	}
}
