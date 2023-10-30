package com.vmware.scg.extensions.sec.cookie;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vmware.scg.extensions.sec.ProfileCookie;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class ProfileCookieParser {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final CookieDecrypter cookieDecrypter;

    public ProfileCookieParser(CookieDecrypter cookieDecrypter) {
        this.cookieDecrypter = cookieDecrypter;
    }

    public ProfileCookie parse(String rawCookie) {
        final String decryptedCookie = cookieDecrypter.decrypt(rawCookie);
        // Do stuff
        final Map<String, Object> values = extractValues(decryptedCookie);
        final List<Integer> allowedAppsId = (List<Integer>) values.get("app-ids");

        return new ProfileCookie(allowedAppsId);
    }

    private Map<String, Object> extractValues(String decryptedCookie) {
        // do stuff
        // For example if the cookie contains a JSON token
        try {
            return objectMapper.readValue(decryptedCookie, HashMap.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
