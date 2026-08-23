package com.contoso.uem;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class DomainBAuthenticator implements Authenticator {
    private final String domain;
    private final String label;

    public DomainBAuthenticator() { this("b", "Domain B"); }

    protected DomainBAuthenticator(String domain, String label) {
        this.domain = domain;
        this.label = label;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(form(context).createForm("domain-login.ftl"));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String b = PocIdentity.normalize(form.getFirst("username"));
        String password = form.getFirst("password");
        FederatedDirectory.User ldapUser = FederatedDirectory.authenticate(
                context.getSession(), context.getRealm(), domain, b, password);
        password = null;
        if (ldapUser == null) {
            fail(context, label + " credentials are invalid.");
            return;
        }
        b = ldapUser.accountName();

        String lookupAttribute = ldapUser.immutableId() == null
                ? PocIdentity.identityAttribute(domain) : PocIdentity.identityAttribute(domain) + "_id";
        String lookupValue = ldapUser.immutableId() == null ? b : ldapUser.immutableId();
        UserModel user = context.getSession().users()
                .searchForUserByUserAttributeStream(context.getRealm(), lookupAttribute, lookupValue)
                .findFirst().orElse(null);
        if (user == null) {
            fail(context, "No " + label + " link exists. Complete linking through Domain A.");
            return;
        }
        context.setUser(user);
        context.success();
    }

    private void fail(AuthenticationFlowContext context, String message) {
        Response response = form(context).setError(message).createForm("domain-login.ftl");
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
    }

    private org.keycloak.forms.login.LoginFormsProvider form(AuthenticationFlowContext context) {
        return context.form().setAttribute("domainLabel", label).setAttribute("domainCode", domain.toUpperCase());
    }

    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
