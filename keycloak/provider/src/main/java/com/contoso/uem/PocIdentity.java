package com.contoso.uem;

import java.util.Locale;

final class PocIdentity {
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

}
