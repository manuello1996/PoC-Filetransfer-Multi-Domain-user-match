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

public final class DomainAAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(context.form().createForm("domain-a-login.ftl"));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String a = PocIdentity.normalize(form.getFirst("a_username"));
        if (!a.matches("[A-Z0-9._-]{1,64}")) {
            fail(context, "Enter a valid simulated Domain A Windows username.", "domain-a-login.ftl");
            return;
        }

        UserModel existing = find(context, PocIdentity.ATTR_A, a);
        if (existing != null) {
            if (!PocIdentity.hasAnyDirectoryLink(existing)) {
                existing.addRequiredAction(LinkDomainBRequiredActionFactory.ID);
            }
            context.setUser(existing);
            context.success();
            return;
        }

        UserModel user = context.getSession().users().addUser(context.getRealm(), "uem-" + UUID.randomUUID());
        user.setEnabled(true);
        user.setSingleAttribute(PocIdentity.ATTR_A, a);
        user.setSingleAttribute("link_status", "UNLINKED");
        user.addRequiredAction(LinkDomainBRequiredActionFactory.ID);
        user.setFirstName(a);
        user.setLastName("Domain-A");
        user.setEmail(a.toLowerCase() + "@a.contoso.com");
        user.setEmailVerified(true);
        context.setUser(user);
        context.success();
    }

    private UserModel find(AuthenticationFlowContext context, String attribute, String value) {
        return context.getSession().users()
                .searchForUserByUserAttributeStream(context.getRealm(), attribute, value)
                .findFirst().orElse(null);
    }

    private void fail(AuthenticationFlowContext context, String message, String template) {
        Response response = context.form().setError(message).createForm(template);
        context.failureChallenge(AuthenticationFlowError.INVALID_USER, response);
    }

    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
