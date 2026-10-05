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
 * Merchant transaction velocity and composite fraud scoring engine utilizing MongoDB,
 * OpenAI explanation generation, and thread-safe fallback stores.
 */
object KtTransactionScorerState {
    val merchantTxStore = ConcurrentHashMap<String, CopyOnWriteArrayList<Map<String, Any>>>()

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
 * Step 1: Queries transaction velocity count for a merchant from MongoDB or in-memory store.
 */
fun abcd_queryMerchantVelocity(merchantId: String): Int {
    try {
        val client = KtTransactionScorerState.mongoClient
        if (client != null) {
            val coll = client.getDatabase("nexis_fraud").getCollection("merchant_orders")
            val filter = org.bson.Document("merchantId", merchantId)
            val count = coll.countDocuments(filter)
            if (count > 0) return count.toInt()
        }
    } catch (_: Throwable) {
        // Fall back to memory
    }

    val history = KtTransactionScorerState.merchantTxStore[merchantId]
    return history?.size ?: 3
}

/**
 * Step 2a: Calculates normalized velocity score based on transaction frequency and volume.
 */
fun efgh_calculateVelocityScore(ordersList: List<Map<String, Any>>): Double {
    if (ordersList.isEmpty()) return 0.05
    val count = ordersList.size
    val totalAmount = ordersList.sumOf { (it["amount"] as? Number)?.toDouble() ?: 0.0 }

    val countScore = (count.toDouble() / 100.0).coerceIn(0.0, 0.5)
    val amountScore = if (totalAmount > 50000.0) 0.5 else (totalAmount / 100000.0)

    return (countScore + amountScore).coerceIn(0.0, 1.0)
}

/**
 * Step 2b: Queries OpenAI to generate human-readable fraud justification explanation.
 */
fun efgh_queryAiFraudExplanation(scoreData: Map<String, Any>): String {
    val service = KtTransactionScorerState.openAiService
    if (service != null) {
        try {
            val prompt = "Provide a concise 1-sentence fraud explanation for data: $scoreData"
            val req = ChatCompletionRequest.builder()
                .model("gpt-3.5-turbo")
                .messages(listOf(ChatMessage("user", prompt)))
                .maxTokens(60)
                .build()
            val reply = service.createChatCompletion(req).choices?.firstOrNull()?.message?.content
            if (!reply.isNullOrBlank()) return reply.trim()
        } catch (_: Throwable) {
            // Heuristic explanation
        }
    }

    val score = (scoreData["composite_score"] as? Number)?.toDouble() ?: 0.1
    return if (score > 0.6) {
        "High transaction velocity and elevated volume detected exceeding safe merchant thresholds."
    } else {
        "Transaction pattern conforms to standard merchant velocity baselines."
    }
}

/**
 * Step 3: Computes composite fraud score combining velocity count, historical volume, and AI explanation.
 */
fun ijkl_computeCompositeScore(merchantId: String, tx: Map<String, Any>): Double {
    val velocityCount = abcd_queryMerchantVelocity(merchantId)
    val history = KtTransactionScorerState.merchantTxStore.computeIfAbsent(merchantId) {
        CopyOnWriteArrayList()
    }
    history.add(tx)

    val velScore = efgh_calculateVelocityScore(history)
    val txAmount = (tx["amount"] as? Number)?.toDouble() ?: 0.0
    val amountRisk = if (txAmount > 25000.0) 0.4 else 0.05

    val preliminaryScore = ((velocityCount.toDouble() / 50.0).coerceIn(0.0, 0.3) * 0.4) +
        (velScore * 0.4) + (amountRisk * 0.2)

    efgh_queryAiFraudExplanation(mapOf(
        "merchantId" to merchantId,
        "composite_score" to preliminaryScore,
        "velocity" to velocityCount
    ))

    return preliminaryScore.coerceIn(0.0, 1.0)
}

/**
 * Step 4: Evaluates merchant fraud risks and returns structured decision with explanation.
 */
fun mnop_evaluateMerchantFraud(merchantId: String, tx: Map<String, Any>): Map<String, Any> {
    val compositeScore = ijkl_computeCompositeScore(merchantId, tx)
    val explanation = efgh_queryAiFraudExplanation(mapOf(
        "merchantId" to merchantId,
        "composite_score" to compositeScore
    ))

    val isFraudulent = compositeScore >= 0.70
    val status = when {
        compositeScore >= 0.70 -> "FLAGGED_FRAUD"
        compositeScore >= 0.40 -> "ELEVATED_RISK"
        else -> "CLEARED"
    }

    return mapOf(
        "merchant_id" to merchantId,
        "composite_score" to compositeScore,
        "status" to status,
        "is_fraudulent" to isFraudulent,
        "explanation" to explanation,
        "evaluated_at" to System.currentTimeMillis()
    )
}
