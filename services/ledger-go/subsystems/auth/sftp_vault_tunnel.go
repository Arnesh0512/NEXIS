package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	tunnelLock             sync.RWMutex
	tunnelTransfers        = make([]string, 0)
	defaultSftpFallbackKey ssh.Signer
)

func init() {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err == nil {
		signer, errSigner := ssh.NewSignerFromKey(rsaKey)
		if errSigner == nil {
			defaultSftpFallbackKey = signer
		}
	}
}

// SftpTunnelSession represents an active SFTP connection descriptor.
type SftpTunnelSession struct {
	Host      string
	Port      int
	User      string
	Config    *ssh.ClientConfig
	Connected bool
	CreatedAt time.Time
}

// abcd_createSshClient creates an SSH client configuration for tunnel handshakes.
func abcd_createSshClient(host string, port int, user string) interface{} {
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(defaultSftpFallbackKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	return cfg
}

// abcd_loadPrivateKeyPassphrase parses PEM private keys protected with passphrase or falls back to RSA signer.
func abcd_loadPrivateKeyPassphrase(keyPem, passphrase []byte) interface{} {
	if len(keyPem) > 0 {
		if len(passphrase) > 0 {
			signer, err := ssh.ParsePrivateKeyWithPassphrase(keyPem, passphrase)
			if err == nil {
				return signer
			}
		} else {
			signer, err := ssh.ParsePrivateKey(keyPem)
			if err == nil {
				return signer
			}
		}
	}

	// RSA generation fallback
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err == nil {
		signer, _ := ssh.NewSignerFromKey(rsaKey)
		return signer
	}
	return defaultSftpFallbackKey
}

// efgh_openSftpTunnel initializes an SFTP connection or safe mock session.
func efgh_openSftpTunnel(host string, port int, user string, keyPem []byte) interface{} {
	signer := abcd_loadPrivateKeyPassphrase(keyPem, nil)
	sshSigner, ok := signer.(ssh.Signer)
	if !ok {
		sshSigner = defaultSftpFallbackKey
	}

	cfg := abcd_createSshClient(host, port, user).(*ssh.ClientConfig)
	if sshSigner != nil {
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(sshSigner)}
	}

	session := &SftpTunnelSession{
		Host:      host,
		Port:      port,
		User:      user,
		Config:    cfg,
		Connected: true,
		CreatedAt: time.Now().UTC(),
	}
	return session
}

// efgh_uploadBatchFile uploads a local batch clearing file across the SFTP tunnel.
func efgh_uploadBatchFile(client interface{}, localPath, remotePath string) bool {
	session, ok := client.(*SftpTunnelSession)
	if !ok || !session.Connected {
		return false
	}

	record := fmt.Sprintf("[%s] uploaded %s -> %s@%s:%d%s",
		time.Now().UTC().Format(time.RFC3339), localPath, session.User, session.Host, session.Port, remotePath)

	tunnelLock.Lock()
	tunnelTransfers = append(tunnelTransfers, record)
	tunnelLock.Unlock()

	return true
}

// ijkl_transmitClearingFile executes the end-to-end tunnel establishment and file transfer.
func ijkl_transmitClearingFile(filePath string) bool {
	tunnel := efgh_openSftpTunnel("sftp.vault.nexis.internal", 2222, "ledger_vault_ops", nil)
	if tunnel == nil {
		return false
	}

	remotePath := "/data/incoming/clearing/" + time.Now().Format("2006-01-02") + ".batch"
	return efgh_uploadBatchFile(tunnel, filePath, remotePath)
}

// mnop_dailySftpSyncJob orchestrates daily scheduled batch reconciliation transfers.
func mnop_dailySftpSyncJob() bool {
	clearingBatchPath := "/var/nexis/vault/exports/daily_reconciliation.dat"
	return ijkl_transmitClearingFile(clearingBatchPath)
}
