package com.nexis.auth.telemetry;
public class LatencyTelemetryMonitor { public static boolean check(long ms) { return ms < 100; } }
