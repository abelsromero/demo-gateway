package com.vmware.scg.extensions.sec;

import com.vmware.scg.extensions.sec.cookie.AuthCookie;
import com.vmware.scg.extensions.sec.cookie.AuthCookieParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
class CookieAuthenticationConverter implements ServerAuthenticationConverter {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthorizationGatewayFilterFactory.class);

    private static final String COOKIE_NAME = "auth-cookie";

    private final AuthCookieParser cookieParser;

    public CookieAuthenticationConverter(AuthCookieParser cookieParser) {
        this.cookieParser = cookieParser;
    }

    // Create Authentication token that represents a request to authenticate, not the actual validated context.
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {

        final List<HttpCookie> httpCookies = exchange.getRequest().getCookies().get(COOKIE_NAME);

        if (httpCookies == null || httpCookies.isEmpty()) {
            log.debug("No auth cookie found");
            // Returning no Authentication translates into 401 Unauthorized
//            return Mono.just(unauthenticatedToken());
            return Mono.empty();
        }

        final HttpCookie httpCookie = httpCookies.get(0);

        AuthCookie authCookie = cookieParser.parse(httpCookie.getValue());

        // Initial cookie validations can be done here, but by definition, the `ServerAuthenticationConverter`.
        // If decryption is considered part of the validation, that is, a cookie is valid
        // if it can be decrypted, the recommendation is:
        //  - create 2 Authentication classes
        //    - the first, holds the encrypted value as-is, and passes it to the ReactiveAuthenticationManager implementation
        //    - the second, represents a valid validated (hence, authenticated) Authentication and is the return from ReactiveAuthenticationManager

        return Mono.just(new CookieAuthentication(authCookie));
    }

    private Authentication unauthenticatedToken() {
        return new CookieAuthentication();
    }
}
