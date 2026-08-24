package com.contoso.uem;

import org.jboss.logging.Logger;
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
        if (accountName.isBlank() || password == null || password.isBlank()) return null;

        DirectoryDomains.Domain directory = DirectoryDomains.find(realm, domain).orElse(null);
        if (directory == null) {
            LOG.warnf("No enabled LDAP federation component was found for Domain %s", domain.toUpperCase());
            return null;
        }
        var component = directory.component();

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
