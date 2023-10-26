package com.vmware.scg.extensions.sec;

import com.vmware.scg.extensions.sec.cookie.AuthCookie;
import com.vmware.scg.extensions.sec.cookie.CookieValidationService;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Component
class CookieAuthenticationManager implements ReactiveAuthenticationManager {

    private final CookieValidationService validationService;

    public CookieAuthenticationManager(CookieValidationService validationService) {
        this.validationService = validationService;
    }

    // Responsible for validating (hence marking the AuthenticationToken as authenticated)
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        var cookieAuthentication = (AuthCookie) authentication.getCredentials();

        boolean authenticated = validate(cookieAuthentication);
        authentication.setAuthenticated(authenticated);

        return Mono.just(authentication);
    }

    private boolean validate(AuthCookie authCookie) {
        // Validate the authentication, for example:
        // - ttl
        // - magic numbers, etc.
        return hasRequiredData(authCookie)
                && !hasExpired(authCookie)
                // Third-party validations can be implemented in decoupled beans
                && validationService.isSessionUnique(authCookie.getSessionId());
    }

    private static boolean hasExpired(AuthCookie authCookie) {
        final var expirationTime = authCookie.getIssuedAt().plus(authCookie.getTtl());
        return LocalDateTime.now().isAfter(expirationTime);
    }

    private static boolean hasRequiredData(AuthCookie authCookie) {
        return authCookie != null
                && authCookie.getIssuedAt() != null
                && authCookie.getTtl() != null;
    }
}
