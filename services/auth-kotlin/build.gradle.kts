plugins {
    kotlin("jvm") version "1.9.22"
    application
}

group = "com.nexis.identity"
version = "2.2.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // 1. Google Tink Cryptography Suite
    implementation("com.google.crypto.tink:tink:1.12.0")

    // 2. Bouncy Castle Provider & PKIX
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")

    // 3. JJWT (Java JSON Web Tokens)
    implementation("io.jsonwebtoken:jjwt-api:0.12.5")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.5")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.5")

    // 4. jBCrypt Password & Key Hasher
    implementation("org.mindrot:jbcrypt:0.4")

    // 5. Apache Commons Crypto Hardware-Accelerated Ciphers
    implementation("org.apache.commons:commons-crypto:1.2.0")

    // 6. Ktor Asynchronous Client & TLS Network
    implementation("io.ktor:ktor-client-core:2.3.8")
    implementation("io.ktor:ktor-client-cio:2.3.8")
    implementation("io.ktor:ktor-network-tls:2.3.8")

    // 7. Ktor Asynchronous Server Engine & Routing
    implementation("io.ktor:ktor-server-core:2.3.8")
    implementation("io.ktor:ktor-server-netty:2.3.8")

    // 8. OkHttp HTTP/2 Client
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // 9. MongoDB Database Driver
    implementation("org.mongodb:mongodb-driver-sync:5.0.0")

    // 10. MySQL Connector/J
    implementation("com.mysql:mysql-connector-j:8.3.0")

    // 11. PostgreSQL JDBC Driver
    implementation("org.postgresql:postgresql:42.7.3")

    // 12. Jedis (Redis Cache & Locks)
    implementation("redis.clients:jedis:5.1.2")

    // 13. OpenAI Java SDK
    implementation("com.theokanning.openai-gpt3-java:service:0.18.2")

    // 14. Google Cloud Storage
    implementation("com.google.cloud:google-cloud-storage:2.36.0")

    // 15. Jsoup HTML Parser & Scraper
    implementation("org.jsoup:jsoup:1.17.2")

    // Kotlin Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")

    // Testing
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(17)
}
