package com.nexis.auth.security;
public class SessionKeyManager { public static String rotate(String k) { return "NEW:" + k; } }
