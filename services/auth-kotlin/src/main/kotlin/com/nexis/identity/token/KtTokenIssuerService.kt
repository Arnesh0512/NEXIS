package com.nexis.identity.token

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import redis.clients.jedis.Jedis
import java.security.Key
import java.util.Base64
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class KtTokenIssuerService(
    private val redisHost: String = "localhost",
    private val redisPort: Int = 6379,
    secretString: String = "nexis-ultra-secure-hmac-sha256-signing-secret-key-32bytes"
) {
    private val hmacKey: Key = Keys.hmacShaKeyFor(secretString.toByteArray(Charsets.UTF_8))
    private val rawSecret = secretString.toByteArray(Charsets.UTF_8)
    private val inMemoryBlacklist = ConcurrentHashMap<String, Long>()

    fun abcd_encodeAccessToken(userId: String, roles: List<String>): String {
        val now = System.currentTimeMillis()
        val validityMillis = 15 * 60 * 1000L // 15 mins

        return try {
            Jwts.builder()
                .setSubject(userId)
                .claim("roles", roles)
                .setIssuedAt(Date(now))
                .setExpiration(Date(now + validityMillis))
                .signWith(hmacKey, SignatureAlgorithm.HS256)
                .compact()
        } catch (_: Throwable) {
            fallbackHmacJwt(
                headerJson = """{"alg":"HS256","typ":"JWT"}""",
                payloadJson = """{"sub":"$userId","roles":"${roles.joinToString(",")}","exp":${(now + validityMillis) / 1000}}"""
            )
        }
    }

    fun abcd_encodeRefreshToken(userId: String): String {
        val now = System.currentTimeMillis()
        val validityMillis = 7 * 24 * 60 * 60 * 1000L // 7 days

        return try {
            Jwts.builder()
                .setSubject(userId)
                .claim("type", "refresh")
                .setIssuedAt(Date(now))
                .setExpiration(Date(now + validityMillis))
                .signWith(hmacKey, SignatureAlgorithm.HS256)
                .compact()
        } catch (_: Throwable) {
            fallbackHmacJwt(
                headerJson = """{"alg":"HS256","typ":"JWT"}""",
                payloadJson = """{"sub":"$userId","type":"refresh","exp":${(now + validityMillis) / 1000}}"""
            )
        }
    }

    fun efgh_issueAuthPair(userId: String, roles: List<String>): Map<String, String> {
        val accessToken = abcd_encodeAccessToken(userId, roles)
        val refreshToken = abcd_encodeRefreshToken(userId)

        return mapOf(
            "accessToken" to accessToken,
            "refreshToken" to refreshToken,
            "tokenType" to "Bearer",
            "userId" to userId
        )
    }

    fun efgh_blacklistToken(tokenStr: String): Boolean {
        return try {
            Jedis(redisHost, redisPort).use { jedis ->
                jedis.setex("blacklist:$tokenStr", 86400, "revoked")
                true
            }
        } catch (_: Throwable) {
            inMemoryBlacklist[tokenStr] = System.currentTimeMillis()
            true
        }
    }

    fun ijkl_renewTokenSession(refreshToken: String): Map<String, String> {
        val isBlacklisted = try {
            Jedis(redisHost, redisPort).use { jedis ->
                jedis.exists("blacklist:$refreshToken")
            }
        } catch (_: Throwable) {
            inMemoryBlacklist.containsKey(refreshToken)
        }

        if (isBlacklisted) {
            return emptyMap()
        }

        val userId = extractSubjectFromToken(refreshToken) ?: "anonymous_user"
        return efgh_issueAuthPair(userId, listOf("ROLE_USER"))
    }

    fun mnop_terminateUserSessions(userId: String): Boolean {
        val revocationKey = "user_session_revoked:$userId"
        return efgh_blacklistToken(revocationKey)
    }

    private fun fallbackHmacJwt(headerJson: String, payloadJson: String): String {
        val encHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.toByteArray(Charsets.UTF_8))
        val encPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.toByteArray(Charsets.UTF_8))
        val signingInput = "$encHeader.$encPayload".toByteArray(Charsets.UTF_8)

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(rawSecret, "HmacSHA256"))
        val sig = mac.doFinal(signingInput)
        val encSig = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)

        return "$encHeader.$encPayload.$encSig"
    }

    private fun extractSubjectFromToken(token: String): String? {
        return try {
            val parts = token.split(".")
            if (parts.size >= 2) {
                val payloadJson = String(Base64.getUrlDecoder().decode(parts[1]), Charsets.UTF_8)
                val subRegex = """"sub"\s*:\s*"([^"]+)"""".toRegex()
                subRegex.find(payloadJson)?.groupValues?.get(1)
            } else null
        } catch (_: Throwable) {
            null
        }
    }
}
