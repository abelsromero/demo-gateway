package com.example.demogateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@SpringBootApplication
public class DemoGatewayApplication {

    private static final Logger log = LoggerFactory.getLogger(DemoGatewayApplication.class);

    /*
    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {

        var securityChain = ServerHttpSecurity.http()
                .headers(headerSpec -> headerSpec.disable())
                .httpBasic(httpBasicSpec -> httpBasicSpec.disable())
//                .formLogin(formLoginSpec -> formLoginSpec.disable())
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

//                .exceptionHandling(exceptionHandlingSpec -> {
//                    exceptionHandlingSpec.authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/login"));
//                })
                .build();

        return securityChain;
//        return ServerHttpSecurity.http()
//                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.anyExchange().permitAll())
//                .csrf(csrfSpec -> csrfSpec.disable())
//                .build();
    }
    */

    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        return http
                .formLogin(Customizer.withDefaults())
                .authenticationManager(authentication -> {
                    log.info("Attempting authentication:" + authentication);
                    return Mono.just(authentication);
                })
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.anyExchange().authenticated())
                .build();
    }

    public static void main(String[] args) {
        SpringApplication.run(DemoGatewayApplication.class, args);
    }

}
