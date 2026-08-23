package com.contoso.uem;

import java.util.Locale;

final class PocIdentity {
    static final String ATTR_A = "identity_a";
    static final String ATTR_B = "identity_b";
    static final String ATTR_C = "identity_c";

    private PocIdentity() {}

    static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    static String normalize(String value) {
        if (value == null) return "";
        String normalized = value.trim();
        int slash = normalized.indexOf('\\');
        if (slash >= 0) normalized = normalized.substring(slash + 1);
        int at = normalized.indexOf('@');
        if (at >= 0) normalized = normalized.substring(0, at);
        return normalized.toUpperCase(Locale.ROOT);
    }

    static String identityAttribute(String domain) {
        return "identity_" + domain;
    }

    static boolean hasAnyDirectoryLink(org.keycloak.models.UserModel user) {
        return user.getFirstAttribute(ATTR_B) != null || user.getFirstAttribute(ATTR_C) != null;
    }
}
