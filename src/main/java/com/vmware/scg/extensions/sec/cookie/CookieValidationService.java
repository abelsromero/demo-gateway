package com.vmware.scg.extensions.sec.cookie;

import org.springframework.stereotype.Component;

@Component
public class CookieValidationService {

    public boolean isSessionUnique(String key) {
        // Call db endpoint
        return true;
    }
}
