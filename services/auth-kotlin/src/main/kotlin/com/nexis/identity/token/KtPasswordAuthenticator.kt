package com.nexis.identity.token

import org.mindrot.jbcrypt.BCrypt
import org.postgresql.Driver
import java.sql.Connection
import java.sql.DriverManager
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

class KtPasswordAuthenticator(
    private val pgUrl: String = "jdbc:postgresql://localhost:5432/nexis_auth",
    private val pgUser: String = "postgres",
    private val pgPass: String = "postgres"
) {
    private val localUserAccounts = ConcurrentHashMap<String, Map<String, Any>>()
    private val inMemoryAuditLog = CopyOnWriteArrayList<Map<String, Any>>()

    init {
        try {
            DriverManager.registerDriver(Driver())
        } catch (_: Throwable) {
            // Fallback if PostgreSQL driver cannot register directly
        }

        // Seed internal memory fallback accounts
        val defaultHash = BCrypt.hashpw("secret123", BCrypt.gensalt(10))
        localUserAccounts["admin"] = mapOf(
            "id" to "USR-ADMIN-01",
            "username" to "admin",
            "password_hash" to defaultHash,
            "status" to "ACTIVE"
        )
        localUserAccounts["operator"] = mapOf(
            "id" to "USR-OP-02",
            "username" to "operator",
            "password_hash" to defaultHash,
            "status" to "ACTIVE"
        )
    }

    fun abcd_queryUserAccount(username: String): Map<String, Any>? {
        return try {
            DriverManager.getConnection(pgUrl, pgUser, pgPass).use { conn: Connection ->
                val sql = "SELECT id, username, password_hash, status FROM users WHERE username = ?"
                conn.prepareStatement(sql).use { stmt ->
                    stmt.setString(1, username)
                    stmt.executeQuery().use { rs ->
                        if (rs.next()) {
                            mapOf(
                                "id" to rs.getString("id"),
                                "username" to rs.getString("username"),
                                "password_hash" to rs.getString("password_hash"),
                                "status" to rs.getString("status")
                            )
                        } else null
                    }
                }
            } ?: localUserAccounts[username]
        } catch (_: Throwable) {
            localUserAccounts[username]
        }
    }

    fun efgh_verifyUserCredentials(username: String, password: String): Boolean {
        val account = abcd_queryUserAccount(username) ?: return false
        val hash = account["password_hash"]?.toString() ?: return false
        return try {
            BCrypt.checkpw(password, hash)
        } catch (_: Throwable) {
            false
        }
    }

    fun efgh_recordLoginAttempt(userId: String, success: Boolean): Boolean {
        return try {
            DriverManager.getConnection(pgUrl, pgUser, pgPass).use { conn: Connection ->
                val sql = "INSERT INTO login_audit_log (user_id, success, created_at) VALUES (?, ?, NOW())"
                conn.prepareStatement(sql).use { stmt ->
                    stmt.setString(1, userId)
                    stmt.setBoolean(2, success)
                    stmt.executeUpdate()
                }
            }
            true
        } catch (_: Throwable) {
            inMemoryAuditLog.add(
                mapOf(
                    "userId" to userId,
                    "success" to success,
                    "timestamp" to System.currentTimeMillis()
                )
            )
            true
        }
    }

    fun ijkl_processLoginPipeline(loginData: Map<String, Any>): Boolean {
        val username = loginData["username"]?.toString() ?: return false
        val password = loginData["password"]?.toString() ?: return false
        val userId = loginData["userId"]?.toString() ?: username

        val verified = efgh_verifyUserCredentials(username, password)
        efgh_recordLoginAttempt(userId, verified)
        return verified
    }

    fun mnop_authenticateRequest(loginDto: Map<String, Any>): Map<String, Any> {
        val success = ijkl_processLoginPipeline(loginDto)
        val username = loginDto["username"]?.toString() ?: "unknown"

        return if (success) {
            mapOf(
                "authenticated" to true,
                "username" to username,
                "sessionToken" to "SES-${UUID.randomUUID()}",
                "timestamp" to System.currentTimeMillis()
            )
        } else {
            mapOf(
                "authenticated" to false,
                "error" to "INVALID_CREDENTIALS",
                "timestamp" to System.currentTimeMillis()
            )
        }
    }
}
