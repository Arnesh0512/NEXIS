package com.nexis.identity.telemetry
class KtLatencyTelemetryMonitor { fun check(ms: Long): Boolean = ms < 100 }
