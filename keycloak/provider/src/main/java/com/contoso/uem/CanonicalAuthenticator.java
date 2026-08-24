package com.contoso.uem;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.UUID;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public final class CanonicalAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(form(context).createForm("canonical-login.ftl"));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> values = context.getHttpRequest().getDecodedFormParameters();
        var client = context.getAuthenticationSession().getClient();
        String domainCode = required(client.getAttribute("uemDomainCode"), "uemDomainCode");
        String domainLabel = required(client.getAttribute("uemDomainLabel"), "uemDomainLabel");
        String domainDnsName = required(client.getAttribute("uemDomainDnsName"), "uemDomainDnsName");
        String accountName = PocIdentity.normalize(values.getFirst("username"));
        if (!accountName.matches("[A-Z0-9._-]{1,64}")) {
            fail(context, "Enter a valid simulated " + domainLabel + " Windows username.");
            return;
        }

        UserModel existing = find(context, PocIdentity.identityAttribute(domainCode), accountName);
        if (existing != null) {
            if (!DirectoryDomains.hasAnyLink(context.getRealm(), existing)) {
                existing.addRequiredAction(LinkDirectoryRequiredActionFactory.ID);
            }
            context.setUser(existing);
            context.success();
            return;
        }

        UserModel user = context.getSession().users().addUser(context.getRealm(), "uem-" + UUID.randomUUID());
        user.setEnabled(true);
        user.setSingleAttribute(PocIdentity.identityAttribute(domainCode), accountName);
        user.setSingleAttribute("link_status", "UNLINKED");
        user.addRequiredAction(LinkDirectoryRequiredActionFactory.ID);
        user.setFirstName(accountName);
        user.setLastName(domainLabel);
        user.setEmail(accountName.toLowerCase() + "@" + domainDnsName);
        user.setEmailVerified(true);
        context.setUser(user);
        context.success();
    }

    private UserModel find(AuthenticationFlowContext context, String attribute, String value) {
        return context.getSession().users().searchForUserByUserAttributeStream(context.getRealm(), attribute, value).findFirst().orElse(null);
    }

    private void fail(AuthenticationFlowContext context, String message) {
        Response response = form(context).setError(message).createForm("canonical-login.ftl");
        context.failureChallenge(AuthenticationFlowError.INVALID_USER, response);
    }

    private org.keycloak.forms.login.LoginFormsProvider form(AuthenticationFlowContext context) {
        String label = required(context.getAuthenticationSession().getClient().getAttribute("uemDomainLabel"), "uemDomainLabel");
        return context.form().setAttribute("domainLabel", label);
    }

    private String required(String value, String attribute) {
        if (value == null || value.isBlank()) throw new IllegalStateException("Missing generated client attribute " + attribute);
        return value;
    }

    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
