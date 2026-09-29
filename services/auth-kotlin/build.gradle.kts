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
    // Google Tink Cryptography
    implementation("com.google.crypto.tink:tink:1.12.0")

    // Ktor TLS & Network
    implementation("io.ktor:ktor-network-tls:2.3.8")
    implementation("io.ktor:ktor-server-core:2.3.8")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")

    // Bouncy Castle (for auxiliary test suite discovery)
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // Testing
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(17)
}
