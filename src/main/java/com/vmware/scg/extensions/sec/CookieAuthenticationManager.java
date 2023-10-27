package com.vmware.scg.extensions.sec;

import com.vmware.scg.extensions.sec.cookie.AuthCookie;
import com.vmware.scg.extensions.sec.cookie.CookieValidationService;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Component
class CookieAuthenticationManager implements ReactiveAuthenticationManager {

    private final CookieValidationService validationService;

    public CookieAuthenticationManager(CookieValidationService validationService) {
        this.validationService = validationService;
    }

    // Responsible for validating (hence marking the AuthenticationToken as authenticated)
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        CookieAuthentication cookieAuthentication = (CookieAuthentication) authentication;

        var authCookie =  ((CookieAuthentication) authentication).getAuthCookie();
        var profileCookie = ((CookieAuthentication) authentication).getProfileCookie();

        boolean authenticated = validate(authCookie, profileCookie);
        authentication.setAuthenticated(authenticated);

        // Extract allowed applications from profile cookie and build authorities
        if (authenticated) {
            List<GrantedAuthority> collect = profileCookie.getAllowedAppsId()
                    .stream()
                    .map(appId -> new SimpleGrantedAuthority("APP_ALLOWED" + appId))
                    .collect(Collectors.toList());

            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            authorities.addAll(collect);
        }

        return Mono.error(new NullPointerException(""));

//        return Mono.just(authentication);
    }

    private boolean validate(AuthCookie authCookie, ProfileCookie profileCookie) {
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
