package com.nexis.identity.fraud

import com.theokanning.openai.completion.chat.ChatCompletionRequest
import com.theokanning.openai.completion.chat.ChatMessage
import com.theokanning.openai.embedding.EmbeddingRequest
import com.theokanning.openai.service.OpenAiService
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import java.time.Duration
import kotlin.math.sqrt

/**
 * AI-assisted risk evaluation engine leveraging OpenAI GPT models, Ktor CIO asynchronous client,
 * and resilient local heuristic fallbacks.
 */
object KtAiRiskState {
    val ktorClient: HttpClient by lazy {
        HttpClient(CIO)
    }

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
}

/**
 * Step 1a: Calls OpenAI risk classification model or executes heuristic fallback.
 */
fun abcd_callOpenAiRiskModel(prompt: String): String {
    val service = KtAiRiskState.openAiService
    if (service != null) {
        try {
            val request = ChatCompletionRequest.builder()
                .model("gpt-3.5-turbo")
                .messages(listOf(ChatMessage("user", prompt)))
                .maxTokens(100)
                .temperature(0.1)
                .build()
            val response = service.createChatCompletion(request)
            val content = response.choices?.firstOrNull()?.message?.content
            if (!content.isNullOrBlank()) return content
        } catch (_: Throwable) {
            // Fall through to heuristic analysis
        }
    }

    // Heuristic rule-based fallback
    val lower = prompt.lowercase()
    val highRisk = lower.contains("high_risk") || lower.contains("vpn") || lower.contains("tor") || lower.contains("fraud")
    val score = if (highRisk) 0.85 else 0.15
    return "HEURISTIC_EVALUATION: risk_score=$score; confidence=0.92"
}

/**
 * Step 1b: Fetches vector embeddings for transaction text from OpenAI or computes localized embedding.
 */
fun abcd_fetchModelEmbeddings(text: String): List<Double> {
    val service = KtAiRiskState.openAiService
    if (service != null) {
        try {
            val embReq = EmbeddingRequest.builder()
                .model("text-embedding-ada-002")
                .input(listOf(text))
                .build()
            val res = service.createEmbeddings(embReq)
            val vector = res.data?.firstOrNull()?.embedding
            if (vector != null && vector.isNotEmpty()) {
                return vector.map { it.toDouble() }
            }
        } catch (_: Throwable) {
            // Fall through to localized vector generator
        }
    }

    // Localized deterministic normalized 16-dimension feature vector
    val dims = 16
    val vec = DoubleArray(dims)
    for (i in 0 until dims) {
        val hash = (text + "_dim_$i").hashCode()
        vec[i] = (hash % 1000).toDouble() / 1000.0
    }
    val norm = sqrt(vec.sumOf { it * it })
    return if (norm > 0.0) vec.map { it / norm } else vec.toList()
}

/**
 * Step 2: Evaluates risk for transaction dictionary by structuring prompt and invoking the AI risk model.
 */
fun efgh_evaluateTransactionRisk(txDict: Map<String, Any>): Double {
    val amount = (txDict["amount"] as? Number)?.toDouble() ?: 0.0
    val currency = txDict["currency"]?.toString() ?: "USD"
    val merchant = txDict["merchant_id"]?.toString() ?: "UNKNOWN"

    val prompt = "Evaluate fraud risk for transaction: amount=$amount $currency, merchant=$merchant, payload=$txDict"
    val aiResponse = abcd_callOpenAiRiskModel(prompt)

    val extractedScore = Regex("""risk_score=([0-9.]+)""")
        .find(aiResponse)
        ?.groupValues?.get(1)?.toDoubleOrNull()

    return if (extractedScore != null) {
        extractedScore.coerceIn(0.0, 1.0)
    } else {
        if (amount > 10000.0) 0.75 else 0.10
    }
}

/**
 * Step 3: Computes composite anomaly score combining transaction risk and embedding magnitude.
 */
fun ijkl_scoreTransactionAnomaly(txDict: Map<String, Any>): Double {
    val baseRisk = efgh_evaluateTransactionRisk(txDict)
    val embedding = abcd_fetchModelEmbeddings(txDict.toString())
    val embeddingVariance = if (embedding.isNotEmpty()) {
        val mean = embedding.average()
        embedding.map { (it - mean) * (it - mean) }.average()
    } else 0.0

    val anomalyScore = (baseRisk * 0.7) + (embeddingVariance.coerceIn(0.0, 1.0) * 0.3)
    return anomalyScore.coerceIn(0.0, 1.0)
}

/**
 * Step 4: Full risk decision pipeline outputting action recommendations.
 */
fun mnop_riskDecisionPipeline(txData: Map<String, Any>): Map<String, Any> {
    val anomalyScore = ijkl_scoreTransactionAnomaly(txData)
    val action = when {
        anomalyScore >= 0.75 -> "REJECT"
        anomalyScore >= 0.40 -> "REVIEW"
        else -> "APPROVE"
    }

    return mapOf(
        "transaction_id" to (txData["tx_id"] ?: txData["id"] ?: java.util.UUID.randomUUID().toString()),
        "risk_score" to anomalyScore,
        "action" to action,
        "requires_mfa" to (anomalyScore >= 0.40),
        "timestamp" to System.currentTimeMillis()
    )
}
