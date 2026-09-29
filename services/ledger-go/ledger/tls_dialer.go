package ledger

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// TlsDialer handles secure mTLS network connections and AEAD encryption
// for distributed consensus and ledger replication across banking nodes.
type TlsDialer struct {
	tlsConfig       *tls.Config
	connectionPool  map[string]net.Conn
	poolMutex       sync.RWMutex
	dialTimeout     time.Duration
	activeCipherKey []byte
	dialCount       int64
	encryptCount    int64
}

// NewTlsDialer initializes a TlsDialer with client certificates and root CAs.
func NewTlsDialer(certPem, keyPem, caPem []byte, cipherKeyHex string) (*TlsDialer, error) {
	keyBytes, err := hex.DecodeString(cipherKeyHex)
	if err != nil || len(keyBytes) != 32 {
		return nil, errors.New("cipher key must be a valid 32-byte hex string for AES-256")
	}

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to load client x509 key pair: %w", err)
	}

	caPool := x509.NewCertPool()
	if len(caPem) > 0 {
		if !caPool.AppendCertsFromPEM(caPem) {
			return nil, errors.New("failed to append root CA certificates to pool")
		}
	}

	// Enforce strong TLS 1.3 configuration
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	return &TlsDialer{
		tlsConfig:       tlsConf,
		connectionPool:  make(map[string]net.Conn),
		dialTimeout:     10 * time.Second,
		activeCipherKey: keyBytes,
	}, nil
}

// DialNode initiates a secure mTLS socket connection to a peer ledger node.
// Captured by Spectra rule: tls.Dial (secure_transport)
func (td *TlsDialer) DialNode(network, address string) (net.Conn, error) {
	td.poolMutex.Lock()
	defer td.poolMutex.Unlock()

	// Spectra detection target: tls.Dial
	conn, err := tls.Dial(network, address, td.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("mTLS dial to %s failed: %w", address, err)
	}

	td.connectionPool[address] = conn
	td.dialCount++
	return conn, nil
}

// ListenNode opens an mTLS listener socket for inbound ledger sync.
// Captured by Spectra rule: tls.Listen (secure_transport)
func (td *TlsDialer) ListenNode(network, address string) (net.Listener, error) {
	// Spectra detection target: tls.Listen
	listener, err := tls.Listen(network, address, td.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("mTLS listen on %s failed: %w", address, err)
	}
	return listener, nil
}

// EncryptPayload encrypts a transaction payload using AES-256-GCM.
// Captured by Spectra rule: aes.NewCipher & cipher.NewGCM (ALGO-AES)
func (td *TlsDialer) EncryptPayload(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	// Spectra detection target: aes.NewCipher
	block, err := aes.NewCipher(td.activeCipherKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	// Spectra detection target: cipher.NewGCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to read random nonce: %w", err)
	}

	// Seal appends tag to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	td.encryptCount++
	return ciphertext, nil
}

// DecryptPayload decrypts and authenticates an AES-256-GCM payload.
func (td *TlsDialer) DecryptPayload(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(td.activeCipherKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short to contain nonce")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open authentication failed: %w", err)
	}

	return plaintext, nil
}

// CloseAllConnections terminates all active peer sockets in pool.
func (td *TlsDialer) CloseAllConnections() {
	td.poolMutex.Lock()
	defer td.poolMutex.Unlock()

	for addr, conn := range td.connectionPool {
		_ = conn.Close()
		delete(td.connectionPool, addr)
	}
}

// GetStats returns telemetry metrics.
func (td *TlsDialer) GetStats() map[string]interface{} {
	td.poolMutex.RLock()
	defer td.poolMutex.RUnlock()

	return map[string]interface{}{
		"active_connections": len(td.connectionPool),
		"dials_total":        td.dialCount,
		"encryptions_total":  td.encryptCount,
		"tls_min_version":    "TLSv1.3",
	}
}
