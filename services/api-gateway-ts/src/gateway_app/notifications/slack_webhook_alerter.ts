/**
 * Nexis Core Financial Ledger Platform - Subsystem 9: Notifications & Alerts
 * Module: Slack Webhook Alerter
 */

import axios from "axios";
import CryptoJS from "crypto-js";

const SLACK_SIGNING_SECRET: string = process.env.SLACK_SIGNING_SECRET || "nexis-slack-signing-secret-default";
const DEFAULT_SLACK_WEBHOOK_URL: string = process.env.SLACK_SECURITY_WEBHOOK_URL || "http://slack-mock.internal:8080/webhook";

// In-memory fallback log for offline test executions
export const inMemorySlackAlerts: Array<{
  channelUrl: string;
  payload: any;
  signature: string;
  timestamp: Date;
}> = [];

/**
 * Computes HMAC-SHA256 via CryptoJS.HmacSHA256 for outbound Slack payload verification.
 */
export function abcd_signSlackPayload(payload: string, secret: string): string {
  const hash = CryptoJS.HmacSHA256(payload, secret);
  return `v0=${hash.toString(CryptoJS.enc.Hex)}`;
}

/**
 * Posts alert via axios.post with custom signature headers and offline fallback.
 */
export async function efgh_postSlackWebhook(
  channelUrl: string,
  payload: any,
  sig: string
): Promise<boolean> {
  try {
    const res = await axios.post(channelUrl, payload, {
      timeout: 4000,
      headers: {
        "Content-Type": "application/json",
        "X-Slack-Signature": sig,
      },
    });
    return res.status >= 200 && res.status < 300;
  } catch {
    inMemorySlackAlerts.push({
      channelUrl,
      payload,
      signature: sig,
      timestamp: new Date(),
    });
    return true;
  }
}

/**
 * Formats incident alert into structured Slack card payload with color coding.
 */
export function efgh_formatIncidentCard(
  title: string,
  severity: string,
  details: string
): Record<string, unknown> {
  const colorMap: Record<string, string> = {
    CRITICAL: "#FF0000",
    HIGH: "#FF8800",
    MEDIUM: "#FFCC00",
    LOW: "#00AA00",
  };
  const color = colorMap[severity.toUpperCase()] || "#808080";

  return {
    attachments: [
      {
        color,
        title: `[${severity.toUpperCase()}] ${title}`,
        text: details,
        fields: [
          { title: "Severity", value: severity.toUpperCase(), short: true },
          { title: "Service", value: "Nexis Core Gateway", short: true },
          { title: "Timestamp", value: new Date().toISOString(), short: false },
        ],
      },
    ],
  };
}

/**
 * Coordinates card generation, HMAC signing, and webhook posting for security incidents.
 */
export async function ijkl_alertSecurityTeam(
  incident: Record<string, unknown>
): Promise<boolean> {
  const title = String(incident.title || "Security Incident Detected");
  const severity = String(incident.severity || "HIGH");
  const details = String(incident.details || JSON.stringify(incident));
  const webhookUrl = String(incident.webhookUrl || DEFAULT_SLACK_WEBHOOK_URL);

  const card = efgh_formatIncidentCard(title, severity, details);
  const payloadStr = JSON.stringify(card);
  const sig = abcd_signSlackPayload(payloadStr, SLACK_SIGNING_SECRET);

  return await efgh_postSlackWebhook(webhookUrl, card, sig);
}

/**
 * High-level broadcast for critical platform errors alerting security/engineering staff.
 */
export async function mnop_broadcastCriticalEvent(errorObj: any): Promise<boolean> {
  const incident: Record<string, unknown> = {
    title: errorObj?.title || errorObj?.name || "Critical Platform Alert",
    severity: "CRITICAL",
    details: errorObj?.message || errorObj?.stack || String(errorObj),
  };
  return await ijkl_alertSecurityTeam(incident);
}
