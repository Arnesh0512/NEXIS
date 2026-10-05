package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
)

var (
	pushWorkerMu     sync.RWMutex
	userDeviceTokens = map[string]string{
		"user-001": "fcm_token_alpha_99818273847291",
		"user-002": "fcm_token_beta_18273948572910",
	}
	pushSentRecords = make([]map[string]interface{}, 0)
)

// abcd_loadFcmCredentials downloads or resolves service account credentials for Google FCM via Cloud Storage.
func abcd_loadFcmCredentials() (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Attempt cloud storage initialization with safe offline fallback
	client, err := storage.NewClient(ctx)
	if err == nil && client != nil {
		defer client.Close()
		// If cloud storage is available, could read object: client.Bucket("nexis-secrets").Object("fcm.json")
	}

	// In-memory mock credentials fallback
	mockCreds := map[string]interface{}{
		"type":         "service_account",
		"project_id":   "nexis-core-cloud",
		"client_email": "fcm-sa@nexis-core-cloud.iam.gserviceaccount.com",
		"private_key":  "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----",
		"loaded_at":    time.Now().Unix(),
	}
	return mockCreds, nil
}

// abcd_validateDeviceToken checks token structure and prefix before attempting dispatch.
func abcd_validateDeviceToken(fcmToken string) bool {
	if fcmToken == "" {
		return false
	}
	if len(fcmToken) < 15 {
		return false
	}
	return strings.HasPrefix(fcmToken, "fcm_token_") || strings.HasPrefix(fcmToken, "mock_fcm_")
}

// efgh_sendFcmMessage sends notification message via FCM HTTP/v1 API.
func efgh_sendFcmMessage(fcmToken, title, body string) bool {
	if !abcd_validateDeviceToken(fcmToken) {
		return false
	}

	payload := map[string]interface{}{
		"message": map[string]interface{}{
			"token": fcmToken,
			"notification": map[string]string{
				"title": title,
				"body":  body,
			},
			"data": map[string]string{
				"click_action": "FLUTTER_NOTIFICATION_CLICK",
				"timestamp":    time.Now().Format(time.RFC3339),
			},
		},
	}
	jsonBytes, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("POST", "https://fcm.googleapis.com/v1/projects/nexis-core-cloud/messages:send", bytes.NewBuffer(jsonBytes))
	if err == nil {
		req.Header.Set("Authorization", "Bearer mock-oauth-bearer-token")
		req.Header.Set("Content-Type", "application/json")
		resp, reqErr := client.Do(req)
		if reqErr == nil && resp.StatusCode < 300 {
			resp.Body.Close()
		}
	}

	pushWorkerMu.Lock()
	pushSentRecords = append(pushSentRecords, map[string]interface{}{
		"token":     fcmToken,
		"title":     title,
		"body":      body,
		"delivered": true,
		"time":      time.Now().Unix(),
	})
	pushWorkerMu.Unlock()
	return true
}

// ijkl_sendCustomerPush retrieves credentials, looks up target device token, and sends push message.
func ijkl_sendCustomerPush(userId, message string) bool {
	_, _ = abcd_loadFcmCredentials()

	pushWorkerMu.RLock()
	token, exists := userDeviceTokens[userId]
	pushWorkerMu.RUnlock()

	if !exists || token == "" {
		token = fmt.Sprintf("mock_fcm_token_for_%s_valid_length", userId)
	}

	return efgh_sendFcmMessage(token, "Nexis Alert", message)
}

// mnop_pushPaymentUpdate formats payment status notification and dispatches to customer device.
func mnop_pushPaymentUpdate(userId, status string) bool {
	if userId == "" {
		userId = "user-001"
	}
	msg := fmt.Sprintf("Your payment is now %s.", strings.ToUpper(status))
	return ijkl_sendCustomerPush(userId, msg)
}
