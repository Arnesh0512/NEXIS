package com.nexis.identity

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Module: Identity Data Mapper & Protocol Transfer Serializer
 *
 * Implements mapping transformations between raw relational database records,
 * domain entity models, and sanitized external DTO representations.
 */
class KtUserMapper {

    data class RawDatabaseRow(
        val id: String,
        val username: String,
        val email: String,
        val tenantId: String,
        val role: String,
        val status: String,
        val createdAtEpoch: Long,
        val lastLoginEpoch: Long?,
        val permissionsDelimited: String
    )

    data class DomainUser(
        val id: String,
        val username: String,
        val email: String,
        val tenantId: String,
        val role: String,
        val isActive: Boolean,
        val isLocked: Boolean,
        val permissions: Set<String>,
        val createdAt: Long,
        val lastLogin: Long?
    )

    data class PublicUserDto(
        val id: String,
        val username: String,
        val tenantId: String,
        val role: String,
        val permissions: List<String>,
        val active: Boolean
    )

    private var totalMappingsCount: Long = 0

    /**
     * Maps database representation to internal domain entity.
     */
    fun fromDatabaseRow(row: RawDatabaseRow): DomainUser {
        totalMappingsCount++

        val permissionsSet = row.permissionsDelimited
            .split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toSet()

        val isActive = row.status.equals("ACTIVE", ignoreCase = true)
        val isLocked = row.status.equals("LOCKED", ignoreCase = true)

        return DomainUser(
            id = row.id,
            username = row.username,
            email = row.email,
            tenantId = row.tenantId,
            role = row.role,
            isActive = isActive,
            isLocked = isLocked,
            permissions = permissionsSet,
            createdAt = row.createdAtEpoch,
            lastLogin = row.lastLoginEpoch
        )
    }

    /**
     * Maps internal domain entity to sanitized public DTO.
     */
    fun toPublicDto(user: DomainUser): PublicUserDto {
        totalMappingsCount++

        return PublicUserDto(
            id = user.id,
            username = user.username,
            tenantId = user.tenantId,
            role = user.role,
            permissions = user.permissions.sorted(),
            active = user.isActive && !user.isLocked
        )
    }

    /**
     * Maps a list of domain entities to public DTO list.
     */
    fun toPublicDtoList(users: List<DomainUser>): List<PublicUserDto> {
        return users.map { toPublicDto(it) }
    }

    /**
     * Validates email string against standard pattern.
     */
    fun isValidEmail(email: String): Boolean {
        if (email.isBlank()) return false
        val regex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$".toRegex()
        return regex.matches(email)
    }

    /**
     * Normalizes tenant identifier strings.
     */
    fun normalizeTenantId(rawTenant: String): String {
        return rawTenant.trim().lowercase().replace("[^a-z0-9_-]".toRegex(), "")
    }

    fun getTotalMappings(): Long = totalMappingsCount
}
