package com.vmware.scg.extensions.sec.cookie;

import java.time.Duration;
import java.time.LocalDateTime;

public class AuthCookie {

    // Add required fields to hande the user
    private final String principal;
    private final LocalDateTime issuedAt;
    private final Duration ttl;
    private final String sessionId;


    public AuthCookie(String principal,
                      LocalDateTime issuedAt,
                      Duration ttl,
                      String sessionId) {
        this.principal = principal;
        this.issuedAt = issuedAt;
        this.ttl = ttl;
        this.sessionId = sessionId;
    }

    public String getPrincipal() {
        return principal;
    }

    public LocalDateTime getIssuedAt() {
        return issuedAt;
    }

    public Duration getTtl() {
        return ttl;
    }

    public String getSessionId() {
        return sessionId;
    }
}
