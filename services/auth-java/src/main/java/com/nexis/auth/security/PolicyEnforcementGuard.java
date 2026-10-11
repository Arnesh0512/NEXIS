package com.nexis.auth.security;
public class PolicyEnforcementGuard { public static boolean enforce(String role) { return "ADMIN".equals(role); } }
