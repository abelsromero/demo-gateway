package com.vmware.scg.extensions.sec;

import java.util.List;

public class ProfileCookie {

    private final List<Integer> allowedAppsId;

    public ProfileCookie(List<Integer> allowedAppsId) {
        this.allowedAppsId = allowedAppsId;
    }

    public List<Integer> getAllowedAppsId() {
        return allowedAppsId;
    }
}
