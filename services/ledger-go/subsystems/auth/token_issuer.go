package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

var (
	tokenSecret       = []byte("auth-subsystem-master-jwt-secret-2026")
	authLock          sync.RWMutex
	blacklistStore    = make(map[string]time.Time)
	userActiveSessions = make(map[string][]string)
	authRedisClient   *redis.Client
)

func init() {
	authRedisClient = redis.NewClient(&redis.Options{
		Addr:        "localhost:6379",
		Password:    "",
		DB:          2,
		DialTimeout: 100 * time.Millisecond,
	})
}

// abcd_encodeAccessToken signs a JWT access token with user ID and roles, expiring in 15 minutes.
func abcd_encodeAccessToken(userId string, roles []string) (string, error) {
	claims := jwt.MapClaims{
		"sub":   userId,
		"roles": roles,
		"type":  "access",
		"iss":   "nexis-auth-subsystem",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(tokenSecret)
}

// abcd_encodeRefreshToken signs a long-lived JWT refresh token expiring in 7 days.
func abcd_encodeRefreshToken(userId string) (string, error) {
	claims := jwt.MapClaims{
		"sub":  userId,
		"type": "refresh",
		"iss":  "nexis-auth-subsystem",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(tokenSecret)
}

// efgh_issueAuthPair generates both access and refresh tokens, recording session metadata.
func efgh_issueAuthPair(userId string, roles []string) (map[string]string, error) {
	accessToken, err := abcd_encodeAccessToken(userId, roles)
	if err != nil {
		return nil, err
	}

	refreshToken, err := abcd_encodeRefreshToken(userId)
	if err != nil {
		return nil, err
	}

	authLock.Lock()
	userActiveSessions[userId] = append(userActiveSessions[userId], accessToken, refreshToken)
	authLock.Unlock()

	return map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    "900",
	}, nil
}

// efgh_blacklistToken marks a token as revoked in memory and in Redis cache.
func efgh_blacklistToken(tokenStr string) bool {
	if tokenStr == "" {
		return false
	}

	authLock.Lock()
	blacklistStore[tokenStr] = time.Now().Add(24 * time.Hour)
	authLock.Unlock()

	if authRedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_ = authRedisClient.Set(ctx, "blacklist:"+tokenStr, "revoked", 24*time.Hour).Err()
	}

	return true
}

func isTokenBlacklisted(tokenStr string) bool {
	authLock.RLock()
	exp, exists := blacklistStore[tokenStr]
	authLock.RUnlock()

	if exists && time.Now().Before(exp) {
		return true
	}

	if authRedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		val, err := authRedisClient.Get(ctx, "blacklist:"+tokenStr).Result()
		if err == nil && val == "revoked" {
			return true
		}
	}
	return false
}

// ijkl_renewTokenSession validates the refresh token, revokes it, and issues a new auth token pair.
func ijkl_renewTokenSession(refreshToken string) (map[string]string, error) {
	if isTokenBlacklisted(refreshToken) {
		return nil, errors.New("refresh token is blacklisted")
	}

	parsedToken, err := jwt.Parse(refreshToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return tokenSecret, nil
	})

	if err != nil || !parsedToken.Valid {
		return nil, errors.New("invalid refresh token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || claims["type"] != "refresh" {
		return nil, errors.New("invalid claim type for refresh")
	}

	userId, ok := claims["sub"].(string)
	if !ok || userId == "" {
		return nil, errors.New("missing sub in claims")
	}

	// Revoke old refresh token (refresh token rotation)
	efgh_blacklistToken(refreshToken)

	// Issue new token pair
	return efgh_issueAuthPair(userId, []string{"authenticated_user"})
}

// mnop_terminateUserSessions revokes all active tokens associated with a given user ID.
func mnop_terminateUserSessions(userId string) bool {
	authLock.Lock()
	tokens, exists := userActiveSessions[userId]
	delete(userActiveSessions, userId)
	authLock.Unlock()

	if !exists || len(tokens) == 0 {
		return true
	}

	for _, tok := range tokens {
		efgh_blacklistToken(tok)
	}

	return true
}
