package com.contoso.uem;

import java.util.Collections;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public final class DirectoryAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "uem-poc-directory";
    private static final DirectoryAuthenticator INSTANCE = new DirectoryAuthenticator();
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "UEM PoC directory Windows SSO"; }
    @Override public String getReferenceCategory() { return "uem-poc"; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() { return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED}; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() { return "Selects a configured LDAP federation from the current client."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return Collections.emptyList(); }
    @Override public Authenticator create(KeycloakSession session) { return INSTANCE; }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}
