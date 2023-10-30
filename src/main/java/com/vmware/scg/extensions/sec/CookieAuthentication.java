package com.vmware.scg.extensions.sec;


import com.vmware.scg.extensions.sec.cookie.AuthCookie;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

/**
 * Holder for the information required to validate a Cookie.
 */
class CookieAuthentication extends AbstractAuthenticationToken {


    // We could make AuthCookie directly extend AbstractAuthenticationToken
    private AuthCookie authCookie;

    private ProfileCookie profileCookie;


    public CookieAuthentication(AuthCookie authCookie, ProfileCookie profileCookie) {
        super(List.of());
        this.authCookie = authCookie;
        this.profileCookie = profileCookie;
    }

    public CookieAuthentication(AuthCookie authCookie, ProfileCookie profileCookie, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.authCookie = authCookie;
        this.profileCookie = profileCookie;
    }

    /**
     * Simple implementation directly storing the cookie.
     * Something
     */
    @Override
    public Object getCredentials() {
        return authCookie;
    }

    @Override
    public Object getPrincipal() {
        return authCookie;
    }

    public AuthCookie getAuthCookie() {
        return authCookie;
    }

    public ProfileCookie getProfileCookie() {
        return profileCookie;
    }
}
