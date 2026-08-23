<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
  <#if section = "header">Domain B VDI
  <#elseif section = "form">
    <div class="poc-note">This form authenticates against the Domain B LDAP container. In production, SPNEGO supplies the identity and no password form is shown.</div>
    <form action="${url.loginAction}" method="post">
      <div class="form-group"><label for="b_username">Windows user</label>
        <input id="b_username" name="b_username" class="form-control" value="PRV-PML" autofocus autocomplete="username" />
      </div>
      <div class="form-group"><label for="b_password">PoC password</label>
        <input id="b_password" name="b_password" class="form-control" type="password" autocomplete="current-password" />
      </div>
      <button class="pf-c-button pf-m-primary pf-m-block btn-lg" type="submit">Continue as Domain B user</button>
    </form>
  </#if>
</@layout.registrationLayout>
