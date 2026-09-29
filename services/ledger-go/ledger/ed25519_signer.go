package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// Ed25519Signer manages high-performance Ed25519 digital signatures
// for signing financial journal blocks and consensus commit votes.
type Ed25519Signer struct {
	keyStore         map[string]ed25519.PrivateKey
	publicKeyStore   map[string]ed25519.PublicKey
	lock             sync.RWMutex
	signaturesTotal  int64
	verifiesTotal    int64
	keysGenerated    int64
}

// NewEd25519Signer creates an Ed25519 cryptographic signer instance.
func NewEd25519Signer() *Ed25519Signer {
	return &Ed25519Signer{
		keyStore:       make(map[string]ed25519.PrivateKey),
		publicKeyStore: make(map[string]ed25519.PublicKey),
	}
}

// GenerateKeyPair generates a new Ed25519 public/private keypair.
// Captured by Spectra rule: ed25519.GenerateKey (ALGO-ED25519)
func (s *Ed25519Signer) GenerateKeyPair(alias string) (ed25519.PublicKey, error) {
	if alias == "" {
		return nil, errors.New("alias cannot be empty")
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	// Spectra detection target: ed25519.GenerateKey
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 key generation failed: %w", err)
	}

	s.keyStore[alias] = priv
	s.publicKeyStore[alias] = pub
	s.keysGenerated++

	return pub, nil
}

// SignMessage signs arbitrary message bytes using the private key associated with alias.
// Captured by Spectra rule: ed25519.Sign (ALGO-ED25519)
func (s *Ed25519Signer) SignMessage(alias string, message []byte) ([]byte, error) {
	s.lock.RLock()
	priv, ok := s.keyStore[alias]
	s.lock.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no private key found for alias: %s", alias)
	}

	// Spectra detection target: ed25519.Sign
	signature := ed25519.Sign(priv, message)

	s.lock.Lock()
	s.signaturesTotal++
	s.lock.Unlock()

	return signature, nil
}

// VerifySignature verifies an Ed25519 signature against message bytes and public key.
// Captured by Spectra rule: ed25519.Verify (ALGO-ED25519)
func (s *Ed25519Signer) VerifySignature(publicKey ed25519.PublicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}

	// Spectra detection target: ed25519.Verify
	isValid := ed25519.Verify(publicKey, message, signature)

	s.lock.Lock()
	s.verifiesTotal++
	s.lock.Unlock()

	return isValid
}

// SignMessageHex signs a message and returns hex-encoded signature.
func (s *Ed25519Signer) SignMessageHex(alias string, message []byte) (string, error) {
	sig, err := s.SignMessage(alias, message)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

// VerifySignatureHex verifies a hex-encoded signature.
func (s *Ed25519Signer) VerifySignatureHex(pubKeyHex string, message []byte, sigHex string) bool {
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}

	return s.VerifySignature(ed25519.PublicKey(pubBytes), message, sigBytes)
}

// ExportPublicKeyHex returns the hex-encoded public key for an alias.
func (s *Ed25519Signer) ExportPublicKeyHex(alias string) (string, error) {
	s.lock.RLock()
	pub, ok := s.publicKeyStore[alias]
	s.lock.RUnlock()

	if !ok {
		return "", fmt.Errorf("alias not found: %s", alias)
	}

	return hex.EncodeToString(pub), nil
}

// ImportPrivateKeyHex stores an existing 64-byte Ed25519 private key.
func (s *Ed25519Signer) ImportPrivateKeyHex(alias, privHex string) error {
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return fmt.Errorf("invalid hex string: %w", err)
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid ed25519 private key length: expected %d, got %d", ed25519.PrivateKeySize, len(privBytes))
	}

	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)

	s.lock.Lock()
	s.keyStore[alias] = priv
	s.publicKeyStore[alias] = pub
	s.lock.Unlock()

	return nil
}

// GetTelemetry returns operational stats for Ed25519 signing.
func (s *Ed25519Signer) GetTelemetry() map[string]interface{} {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return map[string]interface{}{
		"algorithm":         "Ed25519",
		"curve":             "Ed25519",
		"registered_keys":   len(s.keyStore),
		"signatures_total":  s.signaturesTotal,
		"verifies_total":    s.verifiesTotal,
		"keys_generated":    s.keysGenerated,
	}
}
