package com.nexis.identity.fraud

import com.mongodb.client.MongoClient
import com.mongodb.client.MongoClients
import com.theokanning.openai.completion.chat.ChatCompletionRequest
import com.theokanning.openai.completion.chat.ChatMessage
import com.theokanning.openai.service.OpenAiService
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * User behavior anomaly detection engine analyzing geographical velocity, impossible travel jumps,
 * and AI-summarized historical profiles with MongoDB and in-memory fallbacks.
 */
object KtBehaviorState {
    val userHistoryStore = ConcurrentHashMap<String, CopyOnWriteArrayList<Map<String, Any>>>()

    val openAiService: OpenAiService? by lazy {
        val apiKey = System.getenv("OPENAI_API_KEY")
        if (!apiKey.isNullOrBlank()) {
            try {
                OpenAiService(apiKey, Duration.ofSeconds(3))
            } catch (_: Throwable) {
                null
            }
        } else {
            null
        }
    }

    val mongoClient: MongoClient? by lazy {
        try {
            val uri = System.getenv("MONGODB_URI") ?: "mongodb://localhost:27017"
            MongoClients.create(uri)
        } catch (_: Throwable) {
            null
        }
    }
}

/**
 * Step 1: Retrieves user session and transaction history from MongoDB or in-memory state.
 */
fun abcd_fetchUserHistory(userId: String): List<Map<String, Any>> {
    try {
        val client = KtBehaviorState.mongoClient
        if (client != null) {
            val coll = client.getDatabase("nexis_fraud").getCollection("user_activity")
            val filter = org.bson.Document("userId", userId)
            val results = coll.find(filter).limit(20).toList()
            if (results.isNotEmpty()) {
                return results.map { HashMap(it) }
            }
        }
    } catch (_: Throwable) {
        // Fall back to memory
    }

    return KtBehaviorState.userHistoryStore[userId] ?: emptyList()
}

/**
 * Step 2a: Detects impossible travel distance and location jumps between subsequent events.
 */
fun efgh_detectLocationJump(currentLoc: String, lastLoc: String): Boolean {
    if (currentLoc.isBlank() || lastLoc.isBlank()) return false
    val normCurrent = currentLoc.trim().uppercase()
    val normLast = lastLoc.trim().uppercase()

    if (normCurrent == normLast) return false

    // Country or major city distance matrix heuristics
    val disparatePairs = setOf(
        "US" to "CN", "US" to "RU", "US" to "NG", "US" to "IN",
        "GB" to "AU", "DE" to "BR", "FR" to "JP", "NEW YORK" to "TOKYO",
        "LONDON" to "SINGAPORE", "SAN FRANCISCO" to "MOSCOW"
    )

    for ((locA, locB) in disparatePairs) {
        if ((normCurrent.contains(locA) && normLast.contains(locB)) ||
            (normCurrent.contains(locB) && normLast.contains(locA))) {
            return true
        }
    }

    // Default: different country codes indicate potential location jump
    return normCurrent != normLast && normCurrent.length == 2 && normLast.length == 2
}

/**
 * Step 2b: Uses OpenAI to summarize historical user behavior into a baseline profile summary.
 */
fun efgh_summarizeBehaviorWithAi(history: List<Map<String, Any>>): String {
    val service = KtBehaviorState.openAiService
    if (service != null && history.isNotEmpty()) {
        try {
            val historySample = history.takeLast(5).toString()
            val prompt = "Summarize user baseline behavioral tendencies concisely in 1 sentence: $historySample"
            val req = ChatCompletionRequest.builder()
                .model("gpt-3.5-turbo")
                .messages(listOf(ChatMessage("user", prompt)))
                .maxTokens(50)
                .build()
            val content = service.createChatCompletion(req).choices?.firstOrNull()?.message?.content
            if (!content.isNullOrBlank()) return content.trim()
        } catch (_: Throwable) {
            // Heuristic summary
        }
    }

    return "BASELINE_PROFILE: Regular transaction frequency with standard device fingerprinted sessions."
}

/**
 * Step 3: Evaluates overall account security combining history, impossible travel, and AI profiling.
 * Returns true if an anomaly or elevated risk is detected, false otherwise.
 */
fun ijkl_evaluateAccountSecurity(userId: String, event: Map<String, Any>): Boolean {
    val history = abcd_fetchUserHistory(userId)
    val currentLoc = event["location"]?.toString() ?: event["country"]?.toString() ?: "US"
    val lastLoc = history.lastOrNull()?.let {
        it["location"]?.toString() ?: it["country"]?.toString()
    } ?: currentLoc

    val jumpDetected = efgh_detectLocationJump(currentLoc, lastLoc)
    val behaviorSummary = efgh_summarizeBehaviorWithAi(history)

    // Append current event to in-memory profile
    val userEvents = KtBehaviorState.userHistoryStore.computeIfAbsent(userId) {
        CopyOnWriteArrayList()
    }
    userEvents.add(event)

    val deviceChanged = event["new_device"] == true || event["is_new_device"] == true
    val highValue = ((event["amount"] as? Number)?.toDouble() ?: 0.0) > 10000.0

    return jumpDetected || (deviceChanged && highValue) || behaviorSummary.contains("ANOMALOUS")
}

/**
 * Step 4: Triggers step-up multi-factor authentication (MFA) if account security evaluation flags risk.
 */
fun mnop_triggerStepUpAuth(userId: String, event: Map<String, Any>): Boolean {
    val requiresStepUp = ijkl_evaluateAccountSecurity(userId, event)
    return requiresStepUp
}
