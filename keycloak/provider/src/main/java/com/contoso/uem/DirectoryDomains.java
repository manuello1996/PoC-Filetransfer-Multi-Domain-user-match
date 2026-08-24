package com.contoso.uem;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;

final class DirectoryDomains {
    record Domain(String code, String label, String dnsName, String clientId, ComponentModel component) {
        Map<String, String> view() { return Map.of("code", code, "label", label, "dnsName", dnsName); }
    }

    private DirectoryDomains() {}

    static List<Domain> list(RealmModel realm) {
        return realm.getStorageProviders(UserStorageProvider.class)
                .filter(component -> enabled(component) && value(component, "uemDomainCode") != null)
                .map(component -> new Domain(
                        value(component, "uemDomainCode"),
                        fallback(value(component, "uemDomainLabel"), value(component, "uemDomainCode").toUpperCase()),
                        fallback(value(component, "uemDomainDnsName"), ""),
                        fallback(value(component, "uemClientId"), "uem-" + value(component, "uemDomainCode")),
                        component))
                .sorted(Comparator.comparing(Domain::code)).toList();
    }

    static Optional<Domain> find(RealmModel realm, String code) {
        if (code == null) return Optional.empty();
        return list(realm).stream().filter(domain -> domain.code().equals(code)).findFirst();
    }

    static long linkCount(RealmModel realm, UserModel user) {
        return list(realm).stream()
                .filter(domain -> user.getFirstAttribute(PocIdentity.identityAttribute(domain.code())) != null).count();
    }

    static boolean hasAnyLink(RealmModel realm, UserModel user) { return linkCount(realm, user) > 0; }

    private static boolean enabled(ComponentModel component) {
        String enabled = value(component, "enabled");
        return enabled == null || Boolean.parseBoolean(enabled);
    }

    private static String value(ComponentModel component, String key) { return component.getConfig().getFirst(key); }
    private static String fallback(String value, String fallback) { return value == null || value.isBlank() ? fallback : value; }
}
