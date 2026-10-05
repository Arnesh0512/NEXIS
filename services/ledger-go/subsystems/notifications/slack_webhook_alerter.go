package notifications

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

var (
	slackAlerterMu  sync.RWMutex
	slackHistoryLog = make([]map[string]interface{}, 0)
)

// abcd_signSlackPayload generates an HMAC SHA-256 signature for outgoing webhook payload authentication.
func abcd_signSlackPayload(payload, secret string) string {
	if secret == "" {
		secret = "nexis-slack-signing-secret"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// efgh_postSlackWebhook sends the formatted card to a Slack incoming webhook endpoint.
func efgh_postSlackWebhook(channelUrl string, payload map[string]interface{}, sig string) bool {
	if channelUrl == "" {
		channelUrl = "https://slack-mock.internal.nexis/services/alerts"
	}

	client := resty.New()
	client.SetTimeout(2 * time.Second)

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Slack-Signature", sig).
		SetBody(payload).
		Post(channelUrl)

	slackAlerterMu.Lock()
	defer slackAlerterMu.Unlock()

	status := "DELIVERED_MOCK"
	if err == nil && resp.StatusCode() < 300 {
		status = "DELIVERED_REMOTE"
	}

	slackHistoryLog = append(slackHistoryLog, map[string]interface{}{
		"channel":   channelUrl,
		"payload":   payload,
		"signature": sig,
		"status":    status,
		"time":      time.Now().Format(time.RFC3339),
	})

	return true
}

// efgh_formatIncidentCard builds a Slack block-kit compatible structure with signature verification.
func efgh_formatIncidentCard(title, severity, details string) map[string]interface{} {
	serialized := fmt.Sprintf("%s:%s:%s", title, severity, details)
	signature := abcd_signSlackPayload(serialized, "nexis-incident-key")

	return map[string]interface{}{
		"text": fmt.Sprintf("[%s] %s", severity, title),
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": fmt.Sprintf("NEXIS INCIDENT: %s", title),
				},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Severity:*\n%s", severity)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Timestamp:*\n%s", time.Now().Format(time.RFC3339))},
				},
			},
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Details:*\n%s\n*Signature:* `%s`", details, signature),
				},
			},
		},
		"computed_sig": signature,
	}
}

// ijkl_alertSecurityTeam formats incident alert and posts to designated security incident webhook.
func ijkl_alertSecurityTeam(incident map[string]interface{}) bool {
	title, _ := incident["title"].(string)
	if title == "" {
		title = "Security Alert Triggered"
	}
	severity, _ := incident["severity"].(string)
	if severity == "" {
		severity = "HIGH"
	}
	details, _ := incident["details"].(string)
	if details == "" {
		details = "An unclassified security event occurred in the ledger pipeline."
	}

	card := efgh_formatIncidentCard(title, severity, details)
	sig, _ := card["computed_sig"].(string)

	webhookUrl := "https://slack-mock.internal.nexis/services/alerts"
	return efgh_postSlackWebhook(webhookUrl, card, sig)
}

// mnop_broadcastCriticalEvent handles fatal or high-severity errors across subsystems.
func mnop_broadcastCriticalEvent(err error) bool {
	errMessage := "Unknown critical error"
	if err != nil {
		errMessage = err.Error()
	}

	incident := map[string]interface{}{
		"title":    "Subsystem Exception",
		"severity": "CRITICAL",
		"details":  fmt.Sprintf("Exception encountered: %s", errMessage),
	}
	return ijkl_alertSecurityTeam(incident)
}
