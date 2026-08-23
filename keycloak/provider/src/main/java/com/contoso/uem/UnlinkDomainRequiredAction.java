package com.contoso.uem;

import jakarta.ws.rs.core.Response;
import java.util.List;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.ClientModel;

final class UnlinkDomainRequiredAction implements RequiredActionProvider {
    private final String domain;

    UnlinkDomainRequiredAction(String domain) {
        this.domain = domain;
    }

    @Override public InitiatedActionSupport initiatedActionSupport() { return InitiatedActionSupport.SUPPORTED; }
    @Override public void evaluateTriggers(RequiredActionContext context) {}

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        UserModel user = context.getUser();
        String account = user.getFirstAttribute(PocIdentity.identityAttribute(domain));
        if (account == null) {
            context.success();
            return;
        }
        context.challenge(context.form()
                .setAttribute("domainCode", domain.toUpperCase())
                .setAttribute("linkedAccount", account)
                .createForm("unlink-directory.ftl"));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        UserModel user = context.getUser();
        if (linkCount(user) <= 1) {
            Response response = context.form()
                    .setAttribute("domainCode", domain.toUpperCase())
                    .setAttribute("linkedAccount", user.getFirstAttribute(PocIdentity.identityAttribute(domain)))
                    .setError("At least one directory account must remain linked. Add another domain before removing this link.")
                    .createForm("unlink-directory.ftl");
            context.challenge(response);
            return;
        }
        user.removeAttribute(PocIdentity.identityAttribute(domain));
        user.removeAttribute(PocIdentity.identityAttribute(domain) + "_id");
        user.removeAttribute("domain_" + domain + "_dn");
        user.removeAttribute("linked_" + domain + "_at");
        user.setSingleAttribute("link_status", "ACTIVE");
        terminateDomainClientSessions(context, user);
        context.success();
    }

    private void terminateDomainClientSessions(RequiredActionContext context, UserModel user) {
        ClientModel client = context.getRealm().getClientByClientId("uem-" + domain);
        if (client == null) return;
        context.getSession().sessions().getUserSessionsStream(context.getRealm(), user)
                .forEach(userSession -> userSession.removeAuthenticatedClientSessions(List.of(client.getId())));
    }

    private int linkCount(UserModel user) {
        int count = 0;
        if (user.getFirstAttribute(PocIdentity.ATTR_B) != null) count++;
        if (user.getFirstAttribute(PocIdentity.ATTR_C) != null) count++;
        return count;
    }

    @Override public void close() {}
}
