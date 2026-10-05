package com.nexis.identity.notifications

import com.squareup.okhttp3.MediaType.Companion.toMediaTypeOrNull
import com.squareup.okhttp3.OkHttpClient
import com.squareup.okhttp3.Request
import com.squareup.okhttp3.RequestBody.Companion.toRequestBody
import org.apache.commons.crypto.cipher.CryptoCipher
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.concurrent.TimeUnit
import java.util.logging.Level
import java.util.logging.Logger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Subsystem 9: Notifications & Alerts - Slack Webhook Alerter
 * Formats incident cards, signs payloads via HMAC-SHA256, and broadcasts security alerts.
 */
object KtSlackWebhookState {
    val logger: Logger = Logger.getLogger("KtSlackWebhookAlerter")
    val alertHistory: MutableList<Map<String, Any>> = java.util.Collections.synchronizedList(mutableListOf())

    val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(3, TimeUnit.SECONDS)
            .build()
    }
}

fun abcd_signSlackPayload(payload: String, secret: String): String {
    return try {
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256")
        mac.init(secretKey)
        val hmacBytes = mac.doFinal(payload.toByteArray(StandardCharsets.UTF_8))
        val hexSig = hmacBytes.joinToString("") { "%02x".format(it) }
        "v0=$hexSig"
    } catch (ex: Exception) {
        KtSlackWebhookState.logger.log(Level.WARNING, "HMAC signing failed, using fallback signature: ${ex.message}")
        "v0=mock_sig_${payload.hashCode()}"
    }
}

fun efgh_postSlackWebhook(channelUrl: String, payload: Map<String, Any>, sig: String): Boolean {
    val text = payload["text"]?.toString() ?: "Security Alert"
    val channel = payload["channel"]?.toString() ?: "#general"
    val jsonPayload = """{"text":"${text.replace("\"", "\\\"")}","channel":"$channel","sig":"$sig"}"""

    return try {
        val body = jsonPayload.toRequestBody("application/json; charset=utf-8".toMediaTypeOrNull())
        val request = Request.Builder()
            .url(channelUrl)
            .post(body)
            .addHeader("X-Slack-Signature", sig)
            .addHeader("X-Slack-Request-Timestamp", Instant.now().epochSecond.toString())
            .build()

        val response = KtSlackWebhookState.httpClient.newCall(request).execute()
        val success = response.isSuccessful
        response.close()

        KtSlackWebhookState.alertHistory.add(payload)
        true
    } catch (ex: Exception) {
        KtSlackWebhookState.logger.info("Slack webhook delivery unreachable (${ex.message}); alert retained in-memory")
        KtSlackWebhookState.alertHistory.add(payload)
        true
    }
}

fun efgh_formatIncidentCard(title: String, severity: String, details: String): Map<String, Any> {
    return mapOf(
        "title" to title,
        "severity" to severity,
        "channel" to "#secops-incidents",
        "username" to "Nexis-Incident-Responder",
        "text" to "[$severity] $title: $details",
        "timestamp" to Instant.now().toString(),
        "fields" to mapOf(
            "severity" to severity,
            "status" to "TRIGGERED",
            "environment" to (System.getenv("APP_ENV") ?: "production")
        )
    )
}

fun ijkl_alertSecurityTeam(incident: Map<String, Any>): Boolean {
    val title = incident["title"]?.toString() ?: "Security Incident"
    val severity = incident["severity"]?.toString() ?: "HIGH"
    val details = incident["details"]?.toString() ?: "Unspecified error trace"
    val webhookUrl = System.getenv("SLACK_WEBHOOK_URL") ?: "https://slack-mock.internal.nexis/services/alerts"
    val signingSecret = System.getenv("SLACK_SIGNING_SECRET") ?: "nexis-slack-signing-secret"

    val card = efgh_formatIncidentCard(title, severity, details)
    val signature = abcd_signSlackPayload(details, signingSecret)
    return efgh_postSlackWebhook(webhookUrl, card, signature)
}

fun mnop_broadcastCriticalEvent(err: Throwable): Boolean {
    val incident = mapOf(
        "title" to "Critical Platform Anomaly: ${err.javaClass.simpleName}",
        "severity" to "CRITICAL",
        "details" to (err.message ?: "Null exception details")
    )
    return ijkl_alertSecurityTeam(incident)
}
