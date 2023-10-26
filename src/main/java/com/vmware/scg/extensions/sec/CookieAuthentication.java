package com.vmware.scg.extensions.sec;


import com.vmware.scg.extensions.sec.cookie.AuthCookie;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.List;

/**
 * Holder for the information required to validate a Cookie.
 */
class CookieAuthentication extends AbstractAuthenticationToken {


    // We could make AuthCookie directly extend AbstractAuthenticationToken
    private AuthCookie cookie;


    public CookieAuthentication() {
        super(List.of());
        this.cookie = null;
    }

    public CookieAuthentication(AuthCookie cookie) {
        super(List.of());
        this.cookie = cookie;
    }

    /**
     * Simple implementation directly storing the cookie.
     * Something
     */
    @Override
    public Object getCredentials() {
        return cookie;
    }

    @Override
    public Object getPrincipal() {
        return cookie;
    }
}
