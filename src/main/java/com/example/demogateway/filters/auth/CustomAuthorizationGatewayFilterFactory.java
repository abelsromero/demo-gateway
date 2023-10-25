package com.example.demogateway.filters.auth;

/*
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;
import reactor.core.publisher.Mono;

@Component
public class CustomAuthorizationGatewayFilterFactory
        extends AbstractGatewayFilterFactory<CustomAuthorizationGatewayFilterFactory.Config> {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthorizationGatewayFilterFactory.class);

    private final CookieParser cookieParser;
    private final PassiConnector pissaConnector;

    public CustomAuthorizationGatewayFilterFactory(CookieParser cookieParser,
                                                   PassiConnector pissaConnector) {
        super(Config.class);
        this.cookieParser = cookieParser;
        this.pissaConnector = pissaConnector;
    }

    class CustomAuthorizationManager implements ReactiveAuthorizationManager {

        @Override
        public Mono<AuthorizationDecision> check(Mono authentication, Object object) {
            return authentication
                    .map(authentication1 -> {
                        log.info("Attempting authorization:" + authentication1);

                        return new AuthorizationDecision(true);
                    });
        }
    }

    @Override
    public GatewayFilter apply(Config config) {

        var securityChain = ServerHttpSecurity.http()
                .headers(headerSpec -> headerSpec.disable())
                .httpBasic(httpBasicSpec -> httpBasicSpec.disable())
                .formLogin(formLoginSpec -> formLoginSpec.disable())
                .csrf(csrfSpec -> csrfSpec.disable())
                .logout(logoutSpec -> logoutSpec.disable())

                .authenticationManager(authentication -> {
                    log.info("Attempting authentication:" + authentication);

                    return Mono.just(authentication);
                })
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
                        .anyExchange().authenticated())
//                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
//                        .anyExchange()
//                        .access(new CustomAuthorizationManager()))

                .exceptionHandling(exceptionHandlingSpec -> {
                    exceptionHandlingSpec.authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/login"));
                })
                .build();

        return (exchange, chain) -> new WebFilterChainProxy(securityChain).filter(exchange, chain::filter);
    }

    // Make immutable and validated, no need for getters
    @Validated
    static class Config {

        private final Integer id;

        public Config(@NotNull Integer id) {
            this.id = id;
        }
    }

}
*/