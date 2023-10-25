package com.example.demogateway.filters.auth;

import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class CookieParser {

    private final String decryptKey;

    public  CookieParser() {
        this.decryptKey = "decryptKey";
    }

    Map<String, String> decrypt(String rawCookie) {
        // Do stuff
        return Map.of();
    }
}
