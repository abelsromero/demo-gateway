package com.example.demogateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@SpringBootApplication(
        scanBasePackages = {"com.vmware.scg.extensions", "com.example.demogateway"})
public class DemoGatewayApplication {

    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec.anyExchange().permitAll())
                .build();
    }

    public static void main(String[] args) {
        SpringApplication.run(DemoGatewayApplication.class, args);
    }
}
