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

public final class DomainCAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "uem-poc-domain-c";
    private static final DomainCAuthenticator INSTANCE = new DomainCAuthenticator();
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "UEM PoC Domain C Windows SSO"; }
    @Override public String getReferenceCategory() { return "uem-poc"; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() { return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED}; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() { return "Simulates Domain C SPNEGO and resolves the linked canonical user."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return Collections.emptyList(); }
    @Override public Authenticator create(KeycloakSession session) { return INSTANCE; }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}
