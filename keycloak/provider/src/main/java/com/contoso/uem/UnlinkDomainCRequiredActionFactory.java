package com.contoso.uem;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public final class UnlinkDomainCRequiredActionFactory implements RequiredActionFactory {
    public static final String ID = "uem-unlink-domain-c";
    private static final RequiredActionProvider INSTANCE = new UnlinkDomainRequiredAction("c");
    @Override public String getId() { return ID; }
    @Override public String getDisplayText() { return "Unlink Domain C account"; }
    @Override public RequiredActionProvider create(KeycloakSession session) { return INSTANCE; }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}
