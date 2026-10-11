package com.nexis.auth.audit;
public class AuditRetentionPolicy { public static boolean isValid(int days) { return days >= 365; } }
