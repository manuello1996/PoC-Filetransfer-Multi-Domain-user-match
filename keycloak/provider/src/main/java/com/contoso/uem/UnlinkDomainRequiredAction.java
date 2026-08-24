package com.contoso.uem;

import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.ClientModel;

final class UnlinkDomainRequiredAction implements RequiredActionProvider {

    @Override public InitiatedActionSupport initiatedActionSupport() { return InitiatedActionSupport.SUPPORTED; }
    @Override public void evaluateTriggers(RequiredActionContext context) {}

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        UserModel user = context.getUser();
        List<Map<String, String>> accounts = linkedAccounts(context, user);
        if (accounts.isEmpty()) {
            context.success();
            return;
        }
        context.challenge(context.form()
                .setAttribute("linkedAccounts", accounts)
                .createForm("unlink-directory.ftl"));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        UserModel user = context.getUser();
        String domain = context.getHttpRequest().getDecodedFormParameters().getFirst("domain");
        DirectoryDomains.Domain directory = DirectoryDomains.find(context.getRealm(), domain).orElse(null);
        if (directory == null || user.getFirstAttribute(PocIdentity.identityAttribute(domain)) == null) {
            context.challenge(context.form().setAttribute("linkedAccounts", linkedAccounts(context, user)).setError("Select a valid linked directory account.").createForm("unlink-directory.ftl"));
            return;
        }
        if (DirectoryDomains.linkCount(context.getRealm(), user) <= 1) {
            Response response = context.form()
                    .setAttribute("linkedAccounts", linkedAccounts(context, user))
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
        terminateDomainClientSessions(context, user, directory);
        context.success();
    }

    private void terminateDomainClientSessions(RequiredActionContext context, UserModel user, DirectoryDomains.Domain directory) {
        ClientModel client = context.getRealm().getClientByClientId(directory.clientId());
        if (client == null) return;
        context.getSession().sessions().getUserSessionsStream(context.getRealm(), user)
                .forEach(userSession -> userSession.removeAuthenticatedClientSessions(List.of(client.getId())));
    }

    private List<Map<String, String>> linkedAccounts(RequiredActionContext context, UserModel user) {
        return DirectoryDomains.list(context.getRealm()).stream()
                .filter(directory -> user.getFirstAttribute(PocIdentity.identityAttribute(directory.code())) != null)
                .map(directory -> Map.of("code", directory.code(), "label", directory.label(), "account", user.getFirstAttribute(PocIdentity.identityAttribute(directory.code()))))
                .toList();
    }

    @Override public void close() {}
}
