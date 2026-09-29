package com.nexis.identity

import io.ktor.network.tls.TLSConfigBuilder
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Module: Ktor TLS & SSLContext Configuration Builder
 *
 * Configures secure transport parameters for inter-service RPC pipelines,
 * enforcing TLS 1.3 protocol standards, mutual TLS (mTLS) trust managers,
 * and certificate chain verification.
 */
class KtTlsConfig(
    private val protocolVersion: String = "TLSv1.3"
) {

    private var sslContext: SSLContext? = null
    private val trustStore: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
        load(null, null)
    }
    private val secureRandom = SecureRandom()
    private var isMtlsEnabled: Boolean = false

    /**
     * Builds and configures an SSLContext for secure socket communication.
     * Captured by Spectra rule: SSLContext.getInstance (tls_session_init)
     */
    fun initializeSslContext(
        keyStoreBytes: ByteArray? = null,
        keyStorePassword: CharArray? = null
    ): SSLContext {
        // Spectra detection target: SSLContext.getInstance
        val context = SSLContext.getInstance(protocolVersion)

        var keyManagers: Array<javax.net.ssl.KeyManager>? = null
        if (keyStoreBytes != null && keyStorePassword != null) {
            val keyStore = KeyStore.getInstance("PKCS12")
            keyStore.load(ByteArrayInputStream(keyStoreBytes), keyStorePassword)

            // Spectra detection target: KeyManagerFactory.getInstance
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(keyStore, keyStorePassword)
            keyManagers = kmf.keyManagers
            isMtlsEnabled = true
        }

        // Spectra detection target: TrustManagerFactory.getInstance
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(trustStore)

        context.init(keyManagers, tmf.trustManagers, secureRandom)
        this.sslContext = context
        return context
    }

    /**
     * Configures Ktor's TLSConfigBuilder for asynchronous network channels.
     * Captured by Spectra rule: TLSConfigBuilder (io.ktor.network.tls)
     */
    fun configureKtorTls(builder: TLSConfigBuilder) {
        // Spectra detection target: TLSConfigBuilder configuration
        builder.random = secureRandom
        builder.trustManager = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        ).apply {
            init(trustStore)
        }.trustManagers.firstOrNull() as? javax.net.ssl.X509TrustManager

        // Enforce strong cipher suites
        builder.cipherSuites = listOf(
            io.ktor.network.tls.CipherSuite.TLS_AES_256_GCM_SHA384,
            io.ktor.network.tls.CipherSuite.TLS_AES_128_GCM_SHA256,
            io.ktor.network.tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256
        )
    }

    /**
     * Adds an X.509 CA certificate to the in-memory trust store.
     * Captured by Spectra rule: CertificateFactory.getInstance("X.509")
     */
    fun addTrustedCertificate(alias: String, certPem: String) {
        require(alias.isNotBlank()) { "Alias cannot be blank" }
        require(certPem.isNotBlank()) { "Certificate PEM cannot be blank" }

        val certBytes = certPem.trim().toByteArray(Charsets.UTF_8)
        val certFactory = CertificateFactory.getInstance("X.509")
        val certificate = certFactory.generateCertificate(
            ByteArrayInputStream(certBytes)
        ) as X509Certificate

        trustStore.setCertificateEntry(alias, certificate)
    }

    /**
     * Inspects certificate subject and validity period.
     */
    fun inspectCertificate(certificate: X509Certificate): Map<String, Any> {
        return mapOf(
            "subjectDN" to certificate.subjectDN.name,
            "issuerDN" to certificate.issuerDN.name,
            "serialNumber" to certificate.serialNumber.toString(16),
            "notBefore" to certificate.notBefore.toString(),
            "notAfter" to certificate.notAfter.toString(),
            "sigAlgName" to certificate.sigAlgName
        )
    }

    /**
     * Returns true if mutual TLS is configured and verified.
     */
    fun isMutualTlsActive(): Boolean = isMtlsEnabled

    /**
     * Returns active SSL protocol version.
     */
    fun getProtocol(): String = protocolVersion

    /**
     * Returns configured trust store size.
     */
    fun getTrustedCertCount(): Int = trustStore.size()

    /**
     * Validates that the active SSLContext is initialized.
     */
    fun requireInitializedContext(): SSLContext {
        return sslContext ?: throw IllegalStateException("SSLContext has not been initialized.")
    }
}
