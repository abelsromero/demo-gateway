package com.vmware.scg.extensions.sec;


import com.vmware.scg.extensions.sec.cookie.AuthCookie;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;

@Component
public class CustomAuthorizationGatewayFilterFactory
        extends AbstractGatewayFilterFactory<CustomAuthorizationGatewayFilterFactory.Config> {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthorizationGatewayFilterFactory.class);

    private final CookieAuthenticationConverter authenticationConverter;
    private final CookieAuthenticationManager authenticationManager;

    public CustomAuthorizationGatewayFilterFactory(CookieAuthenticationConverter authenticationConverter,
                                                   CookieAuthenticationManager authenticationManager) {
        super(Config.class);
        this.authenticationConverter = authenticationConverter;
        this.authenticationManager = authenticationManager;
    }


    private WebClient webClient;

    @Override
    public GatewayFilter apply(Config config) {

        var authenticationWebFilter = authenticationWebFilter();

        ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> {
                    CookieAuthentication authentication = (CookieAuthentication)securityContext.getAuthentication();
                    AuthCookie credentials = (AuthCookie)authentication.getCredentials();

                    String sessionId = credentials.getSessionId();


                });




        // Use Spring Security DLS builder:
        //  * Disable unnecessary pieces
        //  * Inject custom AuthenticationWebFilter during Authentication phase.
        //  * Setup in 'authorizeExchange' that in order to proceed user needs to be authenticated.
        //      This makes it so that if the cookie could not be validated, an exception is passed to 'exceptionHandling'
        final SecurityWebFilterChain securityChain = ServerHttpSecurity.http()
                .headers(headerSpec -> headerSpec.disable())
                .httpBasic(httpBasicSpec -> httpBasicSpec.disable())
                .csrf(csrfSpec -> csrfSpec.disable())
                .logout(logoutSpec -> logoutSpec.disable())
                .addFilterBefore(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .authorizeExchange(authorizeExchangeSpec -> {
                    authorizeExchangeSpec
                            .anyExchange().hasAuthority("APP_ALLOWED_"+config.id)
                            .anyExchange().authenticated();
                })

                .exceptionHandling(exceptionHandlingSpec -> exceptionHandlingSpec
                                .accessDeniedHandler((exchange, denied) -> {
                                    // TODO check if exception from manager is wrapper in AccessDenied
                                    //   denied.getCause();

                                    ServerHttpResponse response = exchange.getResponse();
                                    // For example only, `Location` should come with status 302
                                    response.setRawStatusCode(600);
                                    response.getHeaders().setLocation(URI.create("/url/to-redirect"));
                                    // Customizing the response
                                    DataBufferFactory dataBufferFactory = response.bufferFactory();
                                    DataBuffer wrap = dataBufferFactory.wrap("error message".getBytes(StandardCharsets.UTF_8));

                                    return response.writeWith(Mono.just(wrap));
                                })
                )
                .build();

        log.info("CustomAuthorizationGatewayFilterFactory securityChain configured");

//        return (exchange, chain) -> new WebFilterChainProxy(securityChain).filter(exchange, chain::filter);
        return (exchange, chain) -> {

            // Passi Extension
            String passiSessionId= "1234567890";
            exchange.getAttributes().put("PASSI_SESSION", passiSessionId);

            // Pre-Filter or Post-Filter
            String passiSession = (String) exchange.getAttributes().get("PASSI_SESSION");


            return
        };
    }

    private AuthenticationWebFilter authenticationWebFilter() {
        var authenticationWebFilter = new AuthenticationWebFilter(authenticationManager);
        authenticationWebFilter.setServerAuthenticationConverter(authenticationConverter);
        return authenticationWebFilter;
    }

    // Make the Config class immutable and validated: no need for getters and manual checks
    @Validated
    static class Config {

        private final Integer id;

        public Config(@NotNull Integer id) {
            this.id = id;
        }
    }
}
