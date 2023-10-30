package com.vmware.scg.extensions.sec;

import com.vmware.scg.extensions.sec.cookie.AuthCookie;
import com.vmware.scg.extensions.sec.cookie.AuthCookieParser;
import com.vmware.scg.extensions.sec.cookie.ProfileCookieParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Component
class CookieAuthenticationConverter implements ServerAuthenticationConverter {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthorizationGatewayFilterFactory.class);

    private static final String AUTH_COOKIE_NAME = "auth-cookie";
    private static final String PROFILE_COOKIE_NAME = "profile-cookie";

    private final AuthCookieParser authCookieParser;
    private final ProfileCookieParser profileCookieParser;

    public CookieAuthenticationConverter(AuthCookieParser cookieParser, ProfileCookieParser profileCookieParser) {
        this.authCookieParser = cookieParser;
        this.profileCookieParser = profileCookieParser;
    }

    // Create Authentication token that represents a request to authenticate, not the actual validated context.
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {

        final var cookies = exchange.getRequest().getCookies();

        if (!isCookiePresent(cookies, AUTH_COOKIE_NAME) && !isCookiePresent(cookies, PROFILE_COOKIE_NAME)) {
            log.debug("No auth & profile cookies found");
            // Returning no Authentication translates into 401 Unauthorized
//            return Mono.just(unauthenticatedToken());
            return Mono.empty();
        }

        AuthCookie authCookie = authCookieParser.parse(getCookieValue(cookies, AUTH_COOKIE_NAME));
        ProfileCookie profileCookie = profileCookieParser.parse(getCookieValue(cookies, PROFILE_COOKIE_NAME));

        // Initial cookie validations can be done here, but by definition, the `ServerAuthenticationConverter`.
        // If decryption is considered part of the validation, that is, a cookie is valid
        // if it can be decrypted, the recommendation is:
        //  - create 2 Authentication classes
        //    - the first, holds the encrypted value as-is, and passes it to the ReactiveAuthenticationManager implementation
        //    - the second, represents a valid validated (hence, authenticated) Authentication and is the return from ReactiveAuthenticationManager

        return Mono.just(new CookieAuthentication(authCookie, profileCookie));
    }

    private boolean isCookiePresent(MultiValueMap<String, HttpCookie> cookies, String cookieName) {
        return Optional.ofNullable(cookies.get(cookieName))
                .map(cookie -> !cookie.isEmpty())
                .orElse(Boolean.FALSE);
    }

    private String getCookieValue(MultiValueMap<String, HttpCookie> cookies, String cookieName) {
        return cookies.get(cookieName).get(0).getValue();
    }

    private Authentication unauthenticatedToken() {
        return new CookieAuthentication(null, null);
    }
}
