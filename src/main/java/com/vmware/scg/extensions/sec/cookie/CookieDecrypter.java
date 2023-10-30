package com.vmware.scg.extensions.sec.cookie;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
class CookieDecrypter {

    private final String decryptKey;

    // Property injection only for example
    CookieDecrypter(@Value("${filter.cookie.decrypt-key}") String decryptKey) {
        this.decryptKey = decryptKey;
    }

    String decrypt(String rawCookie) {
        // do stuff with 'decryptKey'
        byte[] decoded = Base64.getDecoder().decode(rawCookie);
        return new String(decoded);
    }
}
