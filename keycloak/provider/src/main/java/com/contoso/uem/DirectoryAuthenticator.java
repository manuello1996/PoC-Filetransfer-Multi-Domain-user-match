package com.contoso.uem;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public final class DirectoryAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        DirectoryDomains.Domain domain = currentDomain(context);
        if (domain == null) { context.failure(AuthenticationFlowError.INTERNAL_ERROR); return; }
        context.challenge(form(context, domain).createForm("domain-login.ftl"));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        DirectoryDomains.Domain domain = currentDomain(context);
        if (domain == null) { context.failure(AuthenticationFlowError.INTERNAL_ERROR); return; }
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String account = PocIdentity.normalize(form.getFirst("username"));
        String password = form.getFirst("password");
        FederatedDirectory.User ldapUser = FederatedDirectory.authenticate(context.getSession(), context.getRealm(), domain.code(), account, password);
        password = null;
        if (ldapUser == null) { fail(context, domain, domain.label() + " credentials are invalid."); return; }

        String lookupAttribute = ldapUser.immutableId() == null ? PocIdentity.identityAttribute(domain.code()) : PocIdentity.identityAttribute(domain.code()) + "_id";
        String lookupValue = ldapUser.immutableId() == null ? ldapUser.accountName() : ldapUser.immutableId();
        UserModel user = context.getSession().users().searchForUserByUserAttributeStream(context.getRealm(), lookupAttribute, lookupValue).findFirst().orElse(null);
        if (user == null) { fail(context, domain, "No " + domain.label() + " link exists. Complete linking through the canonical workstation."); return; }
        context.setUser(user);
        context.success();
    }

    private DirectoryDomains.Domain currentDomain(AuthenticationFlowContext context) {
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        return DirectoryDomains.list(context.getRealm()).stream().filter(domain -> domain.clientId().equals(clientId)).findFirst().orElse(null);
    }

    private void fail(AuthenticationFlowContext context, DirectoryDomains.Domain domain, String message) {
        Response response = form(context, domain).setError(message).createForm("domain-login.ftl");
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
    }

    private org.keycloak.forms.login.LoginFormsProvider form(AuthenticationFlowContext context, DirectoryDomains.Domain domain) {
        return context.form().setAttribute("domainLabel", domain.label()).setAttribute("domainCode", domain.code().toUpperCase());
    }

    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
