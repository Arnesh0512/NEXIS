package com.nexis.identity.audit
class KtAuditRetentionPolicy { fun isValid(days: Int): Boolean = days >= 365 }
