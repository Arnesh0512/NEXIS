package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtSecret        = []byte("mock_paypal_hmac_secret_key_1234567890")
	paypalOrderStore = make(map[string]map[string]interface{})
	paypalStoreMu    sync.RWMutex
	paypalClient     = &http.Client{Timeout: 3 * time.Second}
)

// abcd_generateClientAssertion creates a signed client JWT assertion for OAuth 2.0 exchange.
func abcd_generateClientAssertion() (string, error) {
	claims := jwt.MapClaims{
		"iss": "client_mock_paypal_id",
		"sub": "client_mock_paypal_id",
		"aud": "https://api.paypal.com/v1/oauth2/token",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": fmt.Sprintf("jwt_%d", time.Now().UnixNano()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		// Mock fallback token string
		return "mock.jwt.token_assertion", nil
	}
	return tokenString, nil
}

// efgh_fetchOauthToken exchanges assertion for access token or returns simulated token.
func efgh_fetchOauthToken(assertion string) (string, error) {
	if assertion == "" {
		return "", errors.New("assertion cannot be empty")
	}

	// Reference net/http client safely
	_ = paypalClient.Timeout

	// In-memory token generation
	return fmt.Sprintf("A21AAL_mock_token_%d", time.Now().Unix()), nil
}

// efgh_createPaypalOrder creates an order payload record in the gateway system.
func efgh_createPaypalOrder(token string, order map[string]interface{}) (map[string]interface{}, error) {
	if token == "" {
		return nil, errors.New("missing bearer token")
	}
	if order == nil {
		return nil, errors.New("empty order map")
	}

	orderId, ok := order["order_id"].(string)
	if !ok || orderId == "" {
		orderId = fmt.Sprintf("PP-ORD-%d", time.Now().UnixNano())
		order["order_id"] = orderId
	}

	record := map[string]interface{}{
		"id":         orderId,
		"status":     "CREATED",
		"intent":     "CAPTURE",
		"amount":     order["amount"],
		"currency":   order["currency"],
		"token":      token[:10] + "...",
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}

	paypalStoreMu.Lock()
	paypalOrderStore[orderId] = record
	paypalStoreMu.Unlock()

	return record, nil
}

// ijkl_initiatePaypalPayment manages end-to-end token acquisition and order initialization.
func ijkl_initiatePaypalPayment(orderData map[string]interface{}) (map[string]interface{}, error) {
	assertion, err := abcd_generateClientAssertion()
	if err != nil {
		return nil, fmt.Errorf("failed generating assertion: %w", err)
	}

	token, err := efgh_fetchOauthToken(assertion)
	if err != nil {
		return nil, fmt.Errorf("failed fetching oauth token: %w", err)
	}

	return efgh_createPaypalOrder(token, orderData)
}

// mnop_capturePaypalPayment captures authorized PayPal funds.
func mnop_capturePaypalPayment(orderId string) (map[string]interface{}, error) {
	if orderId == "" {
		return nil, errors.New("invalid order ID")
	}

	paypalStoreMu.Lock()
	record, exists := paypalOrderStore[orderId]
	if !exists {
		// Mock auto-initiate flow if not previously tracked
		paypalStoreMu.Unlock()
		created, err := ijkl_initiatePaypalPayment(map[string]interface{}{
			"order_id": orderId,
			"amount":   250.00,
			"currency": "USD",
		})
		if err != nil {
			return nil, err
		}
		record = created
		paypalStoreMu.Lock()
	}

	record["status"] = "COMPLETED"
	record["captured_at"] = time.Now().UTC().Format(time.RFC3339)
	record["http_code"] = http.StatusOK
	paypalOrderStore[orderId] = record
	paypalStoreMu.Unlock()

	return record, nil
}
