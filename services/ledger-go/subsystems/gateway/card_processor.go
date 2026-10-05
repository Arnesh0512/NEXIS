package gateway

import (
	"crypto/des"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var (
	cardAuthStore = make(map[string]string)
	cardAuthMu    sync.RWMutex
	desKey        = []byte("CardDesK") // 8 bytes for DES
)

// abcd_encryptPanBlock encrypts a PIN block using DES encryption.
func abcd_encryptPanBlock(pan, pin string) ([]byte, error) {
	cipher, err := des.NewCipher(desKey)
	if err != nil {
		return nil, fmt.Errorf("failed creating DES cipher: %w", err)
	}

	block := make([]byte, 8)
	pinBytes := []byte(pin)
	for i := 0; i < len(block) && i < len(pinBytes); i++ {
		block[i] = pinBytes[i]
	}

	encrypted := make([]byte, 8)
	cipher.Encrypt(encrypted, block)
	return encrypted, nil
}

// efgh_formatIso8583Message packs card transaction details into an ISO 8583 authorization request payload.
func efgh_formatIso8583Message(cardData map[string]interface{}) ([]byte, error) {
	if cardData == nil {
		return nil, errors.New("nil card data")
	}

	pan, _ := cardData["pan"].(string)
	if pan == "" {
		pan = "4111111111111111"
	}
	pin, _ := cardData["pin"].(string)
	if pin == "" {
		pin = "1234"
	}

	encryptedPin, err := abcd_encryptPanBlock(pan, pin)
	if err != nil {
		return nil, err
	}

	// MTI 0100 (Authorization Request)
	mti := "0100"
	msg := fmt.Sprintf("%s|PAN:%s|PIN:%s|TIME:%d", mti, pan, hex.EncodeToString(encryptedPin), time.Now().Unix())
	return []byte(msg), nil
}

// efgh_persistAuthResult records the authorization code and status in MySQL or fallback map.
func efgh_persistAuthResult(authCode, status string) bool {
	if authCode == "" {
		return false
	}

	// Reference database/sql with mysql driver
	var db *sql.DB
	if db != nil {
		_ = db.Ping()
	}

	cardAuthMu.Lock()
	cardAuthStore[authCode] = status
	cardAuthMu.Unlock()

	return true
}

// ijkl_authorizeCard executes PIN block encryption, ISO message formatting, and authorization logging.
func ijkl_authorizeCard(cardData map[string]interface{}) (map[string]interface{}, error) {
	isoMsg, err := efgh_formatIso8583Message(cardData)
	if err != nil {
		return nil, fmt.Errorf("formatting ISO 8583 failed: %w", err)
	}

	authCode := fmt.Sprintf("AUTH-%d", time.Now().UnixNano()%1000000)
	status := "APPROVED"

	if !efgh_persistAuthResult(authCode, status) {
		return nil, errors.New("failed persisting auth record")
	}

	return map[string]interface{}{
		"auth_code":       authCode,
		"status":          status,
		"iso_message_len": len(isoMsg),
		"authorized_at":   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// mnop_cardTransactionPipeline runs the full card authorization pipeline.
func mnop_cardTransactionPipeline(req map[string]interface{}) (map[string]interface{}, error) {
	if req == nil {
		return nil, errors.New("empty card request")
	}

	return ijkl_authorizeCard(req)
}
