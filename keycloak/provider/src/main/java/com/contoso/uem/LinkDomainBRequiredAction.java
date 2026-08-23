package com.contoso.uem;

import java.time.Instant;
import java.util.Set;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.UserModel;

public final class LinkDomainBRequiredAction implements RequiredActionProvider {
    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        // The realm registers this as a default action for every newly created user.
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        context.challenge(context.form().createForm("link-directory.ftl"));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String domain = form.getFirst("domain");
        String b = PocIdentity.normalize(form.getFirst("username"));
        String password = form.getFirst("password");
        if (!Set.of("b", "c").contains(domain)) {
            challenge(context, "Select a valid directory domain.");
            return;
        }
        FederatedDirectory.User ldapUser = FederatedDirectory.authenticate(
                context.getSession(), context.getRealm(), domain, b, password);
        password = null;

        if (ldapUser == null) {
            challenge(context, "Domain " + domain.toUpperCase() + " credentials are invalid; no link was created.");
            return;
        }

        String identityAttribute = PocIdentity.identityAttribute(domain);
        String uniquenessAttribute = ldapUser.immutableId() == null ? identityAttribute : identityAttribute + "_id";
        String uniquenessValue = ldapUser.immutableId() == null ? ldapUser.accountName() : ldapUser.immutableId();
        UserModel alreadyLinked = context.getSession().users()
                .searchForUserByUserAttributeStream(context.getRealm(), uniquenessAttribute, uniquenessValue)
                .findFirst().orElse(null);
        if (alreadyLinked != null && !alreadyLinked.getId().equals(context.getUser().getId())) {
            challenge(context, "That Domain " + domain.toUpperCase() + " identity is already linked to another account.");
            return;
        }

        UserModel user = context.getUser();
        user.setSingleAttribute(identityAttribute, ldapUser.accountName());
        if (ldapUser.immutableId() != null) user.setSingleAttribute(identityAttribute + "_id", ldapUser.immutableId());
        if (ldapUser.dn() != null) user.setSingleAttribute("domain_" + domain + "_dn", ldapUser.dn());
        user.setSingleAttribute("linked_" + domain + "_at", Instant.now().toString());
        user.setSingleAttribute("linked_at", Instant.now().toString());
        user.setSingleAttribute("link_method", "SELF_SERVICE_USER_FEDERATION");
        user.setSingleAttribute("link_status", "ACTIVE");
        context.success();
    }

    private void challenge(RequiredActionContext context, String message) {
        Response response = context.form().setError(message).createForm("link-directory.ftl");
        context.challenge(response);
    }

    @Override public void close() {}
}
