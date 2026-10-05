package com.nexis.identity.vault

import org.mindrot.jbcrypt.BCrypt
import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.ConcurrentHashMap

class KtCredentialHasher(
    private val jdbcUrl: String = "jdbc:mysql://localhost:3306/nexis_auth",
    private val dbUser: String = "nexis_user",
    private val dbPass: String = "nexis_secret"
) {
    private val inMemoryCredentialStore = ConcurrentHashMap<String, String>()

    fun abcd_hashPassword(rawPassword: String): String {
        return BCrypt.hashpw(rawPassword, BCrypt.gensalt(12))
    }

    fun abcd_verifyPassword(rawPassword: String, hashed: String): Boolean {
        return try {
            BCrypt.checkpw(rawPassword, hashed)
        } catch (_: Throwable) {
            false
        }
    }

    fun efgh_storeUserCredential(userId: String, rawPassword: String): Boolean {
        val hashedPassword = abcd_hashPassword(rawPassword)

        return try {
            DriverManager.getConnection(jdbcUrl, dbUser, dbPass).use { conn: Connection ->
                val sql = "REPLACE INTO user_credentials (user_id, password_hash, updated_at) VALUES (?, ?, NOW())"
                conn.prepareStatement(sql).use { stmt ->
                    stmt.setString(1, userId)
                    stmt.setString(2, hashedPassword)
                    stmt.executeUpdate()
                }
            }
            true
        } catch (_: Throwable) {
            inMemoryCredentialStore[userId] = hashedPassword
            true
        }
    }

    fun efgh_checkUserLogin(userId: String, rawPassword: String): Boolean {
        val storedHash = try {
            DriverManager.getConnection(jdbcUrl, dbUser, dbPass).use { conn: Connection ->
                val sql = "SELECT password_hash FROM user_credentials WHERE user_id = ?"
                conn.prepareStatement(sql).use { stmt ->
                    stmt.setString(1, userId)
                    stmt.executeQuery().use { rs ->
                        if (rs.next()) rs.getString("password_hash") else null
                    }
                }
            } ?: inMemoryCredentialStore[userId]
        } catch (_: Throwable) {
            inMemoryCredentialStore[userId]
        }

        if (storedHash == null) return false
        return abcd_verifyPassword(rawPassword, storedHash)
    }

    fun ijkl_credentialVerificationFlow(loginReq: Map<String, Any>): Boolean {
        val userId = loginReq["userId"]?.toString() ?: loginReq["username"]?.toString() ?: return false
        val rawPassword = loginReq["password"]?.toString() ?: return false
        return efgh_checkUserLogin(userId, rawPassword)
    }

    fun mnop_adminResetCredential(userId: String, newPass: String): Boolean {
        return efgh_storeUserCredential(userId, newPass)
    }
}
