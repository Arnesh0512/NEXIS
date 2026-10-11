package com.nexis.identity.audit
class KtAuditCryptoHasher { fun hashData(d: String): String = d.hashCode().toString() }
