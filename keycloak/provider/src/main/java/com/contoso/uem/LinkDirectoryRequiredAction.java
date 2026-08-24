package com.contoso.uem;

import java.time.Instant;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.UserModel;

public final class LinkDirectoryRequiredAction implements RequiredActionProvider {
    @Override public InitiatedActionSupport initiatedActionSupport() { return InitiatedActionSupport.SUPPORTED; }
    @Override public void evaluateTriggers(RequiredActionContext context) {}

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        context.challenge(form(context).createForm("link-directory.ftl"));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> values = context.getHttpRequest().getDecodedFormParameters();
        String domainCode = values.getFirst("domain");
        String accountName = PocIdentity.normalize(values.getFirst("username"));
        String password = values.getFirst("password");
        DirectoryDomains.Domain directory = DirectoryDomains.find(context.getRealm(), domainCode).orElse(null);
        if (directory == null) { challenge(context, "Select a valid directory domain."); return; }

        FederatedDirectory.User ldapUser = FederatedDirectory.authenticate(context.getSession(), context.getRealm(), domainCode, accountName, password);
        password = null;
        if (ldapUser == null) { challenge(context, directory.label() + " credentials are invalid; no link was created."); return; }

        String identityAttribute = PocIdentity.identityAttribute(domainCode);
        String uniquenessAttribute = ldapUser.immutableId() == null ? identityAttribute : identityAttribute + "_id";
        String uniquenessValue = ldapUser.immutableId() == null ? ldapUser.accountName() : ldapUser.immutableId();
        UserModel alreadyLinked = context.getSession().users().searchForUserByUserAttributeStream(context.getRealm(), uniquenessAttribute, uniquenessValue).findFirst().orElse(null);
        if (alreadyLinked != null && !alreadyLinked.getId().equals(context.getUser().getId())) {
            challenge(context, "That " + directory.label() + " identity is already linked to another account.");
            return;
        }

        UserModel user = context.getUser();
        user.setSingleAttribute(identityAttribute, ldapUser.accountName());
        if (ldapUser.immutableId() != null) user.setSingleAttribute(identityAttribute + "_id", ldapUser.immutableId());
        if (ldapUser.dn() != null) user.setSingleAttribute("domain_" + domainCode + "_dn", ldapUser.dn());
        user.setSingleAttribute("linked_" + domainCode + "_at", Instant.now().toString());
        user.setSingleAttribute("linked_at", Instant.now().toString());
        user.setSingleAttribute("link_method", "SELF_SERVICE_USER_FEDERATION");
        user.setSingleAttribute("link_status", "ACTIVE");
        context.success();
    }

    private void challenge(RequiredActionContext context, String message) {
        Response response = form(context).setError(message).createForm("link-directory.ftl");
        context.challenge(response);
    }

    private org.keycloak.forms.login.LoginFormsProvider form(RequiredActionContext context) {
        return context.form().setAttribute("directoryDomains", DirectoryDomains.list(context.getRealm()).stream().map(DirectoryDomains.Domain::view).toList());
    }

    @Override public void close() {}
}
