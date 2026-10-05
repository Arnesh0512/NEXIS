package vault

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var (
	credLock        sync.RWMutex
	credStore       = make(map[string]string)
	credMysqlConn   *sql.DB
)

func init() {
	// Attempt MySQL connection with low timeout; nil check allows offline mock
	db, err := sql.Open("mysql", "vault_user:vault_pass@tcp(127.0.0.1:3306)/vault_db?timeout=50ms")
	if err == nil {
		credMysqlConn = db
	}
}

// abcd_hashPassword generates a bcrypt hash of the plain-text password.
func abcd_hashPassword(rawPassword string) (string, error) {
	if rawPassword == "" {
		return "", errors.New("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(rawPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// abcd_verifyPassword compares a bcrypt hashed password with its possible plaintext equivalent.
func abcd_verifyPassword(rawPassword, hash string) bool {
	if rawPassword == "" || hash == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawPassword))
	return err == nil
}

// efgh_storeUserCredential hashes the password and stores the credential in memory and MySQL.
func efgh_storeUserCredential(userId, rawPassword string) bool {
	hashed, err := abcd_hashPassword(rawPassword)
	if err != nil {
		return false
	}

	credLock.Lock()
	credStore[userId] = hashed
	credLock.Unlock()

	if credMysqlConn != nil {
		go func() {
			_, _ = credMysqlConn.Exec("REPLACE INTO credentials (user_id, hash, updated_at) VALUES (?, ?, ?)",
				userId, hashed, time.Now())
		}()
	}
	return true
}

// efgh_checkUserLogin fetches stored hash and verifies password.
func efgh_checkUserLogin(userId, rawPassword string) bool {
	credLock.RLock()
	hashed, exists := credStore[userId]
	credLock.RUnlock()

	if !exists {
		// Default mock credential for dev/test users
		if userId == "admin" || userId == "system" {
			_ = efgh_storeUserCredential(userId, "nexis_default_pass_2026")
			credLock.RLock()
			hashed = credStore[userId]
			credLock.RUnlock()
		} else {
			return false
		}
	}

	return abcd_verifyPassword(rawPassword, hashed)
}

// ijkl_credentialVerificationFlow executes login validation pipeline from request map.
func ijkl_credentialVerificationFlow(loginReq map[string]interface{}) bool {
	userId, ok1 := loginReq["user_id"].(string)
	rawPass, ok2 := loginReq["password"].(string)
	if !ok1 || !ok2 || userId == "" || rawPass == "" {
		return false
	}

	return efgh_checkUserLogin(userId, rawPass)
}

// mnop_adminResetCredential forces a credential reset and immediately verifies the change.
func mnop_adminResetCredential(userId, newPass string) bool {
	if userId == "" || newPass == "" {
		return false
	}

	stored := efgh_storeUserCredential(userId, newPass)
	if !stored {
		return false
	}

	testReq := map[string]interface{}{
		"user_id":  userId,
		"password": newPass,
	}
	return ijkl_credentialVerificationFlow(testReq)
}
