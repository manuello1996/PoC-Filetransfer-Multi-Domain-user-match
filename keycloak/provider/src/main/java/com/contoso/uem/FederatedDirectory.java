package com.contoso.uem;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;

final class FederatedDirectory {
    private static final Logger LOG = Logger.getLogger(FederatedDirectory.class);
    record User(String accountName, String immutableId, String dn) {}

    private FederatedDirectory() {}

    static User authenticate(KeycloakSession session, RealmModel realm, String domain, String username, String password) {
        String accountName = PocIdentity.normalize(username);
        if (!("b".equals(domain) || "c".equals(domain))
                || accountName.isBlank() || password == null || password.isBlank()) return null;

        String federationName = "domain-" + domain + "-ldap-poc";
        ComponentModel component = realm.getStorageProviders(UserStorageProvider.class)
                .filter(candidate -> federationName.equals(candidate.getName()))
                .filter(candidate -> candidate.getConfig().getFirst("enabled") == null
                        || Boolean.parseBoolean(candidate.getConfig().getFirst("enabled")))
                .findFirst().orElse(null);
        if (component == null) {
            LOG.warnf("No enabled LDAP federation component was found for Domain %s", domain.toUpperCase());
            return null;
        }

        try {
            UserStorageProvider storageProvider = session.getProvider(UserStorageProvider.class, component);
            if (!(storageProvider instanceof LDAPStorageProvider provider)) {
                LOG.warnf("Federation %s did not resolve to an LDAPStorageProvider (resolved type: %s)",
                        component.getName(), storageProvider == null ? "null" : storageProvider.getClass().getName());
                return null;
            }
            LDAPObject ldapUser = provider.loadLDAPUserByUsername(realm, accountName);
            if (ldapUser == null) {
                LOG.infof("Federation %s did not find account %s", component.getName(), accountName);
                return null;
            }
            provider.getLdapIdentityStore().validatePassword(ldapUser, password);
            String loginAttribute = component.getConfig().getFirst("usernameLDAPAttribute");
            String resolvedAccountName = PocIdentity.normalize(ldapUser.getAttributeAsString(loginAttribute));
            return new User(resolvedAccountName, ldapUser.getUuid(), ldapUser.getDn().toString());
        } catch (Exception error) {
            // Lookup and password failures deliberately have the same externally visible result.
            LOG.infof("Federation authentication failed for Domain %s account %s (%s)",
                    domain.toUpperCase(), accountName, error.getClass().getSimpleName());
            return null;
        }
    }
}
