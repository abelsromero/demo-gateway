package com.example.demogateway.filters.auth;

import org.springframework.stereotype.Component;

@Component
public class PassiConnector {


    boolean isSessionUnique(String key) {
        // Call PASSI db endpoint
        return true;
    }
}
