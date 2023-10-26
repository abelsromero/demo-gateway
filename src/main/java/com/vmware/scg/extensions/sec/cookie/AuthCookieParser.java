package com.vmware.scg.extensions.sec.cookie;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.convert.DurationStyle;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuthCookieParser {

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private final String decryptKey;

    // Inject configurations wt
    AuthCookieParser(@Value("${filter.cookie.decrypt-key}") String decryptKey) {
        this.decryptKey = decryptKey;
    }

    public AuthCookie parse(String rawCookie) {
        final String decryptedCookie = decrypt(rawCookie);
        // Do stuff
        final Map<String, String> values = extractValues(decryptedCookie);
        String username = values.get("username");
        // Take into account time zone
        LocalDateTime issuedAt = LocalDateTime.parse(values.get("issued-at"));
        Duration ttl = DurationStyle.detectAndParse(values.get("ttl"));
        String sessionId = values.get("session-id");

        return new AuthCookie(username, issuedAt, ttl, sessionId);
    }

    private Map<String, String> extractValues(String decryptedCookie) {
        // do stuff
        // For example if the cookie contains a JSON token
        try {
            return objectMapper.readValue(decryptedCookie, HashMap.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    // Ideally split the decryption logic into a class if logic or configuration is more complex than a few lines
    private String decrypt(String rawCookie) {
        // do stuff
        byte[] decoded = Base64.getDecoder().decode(rawCookie);
        return new String(decoded);
    }
}
