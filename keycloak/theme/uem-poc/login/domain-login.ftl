<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
  <#if section = "header">${domainLabel} VDI
  <#elseif section = "form">
    <div class="poc-note">This form authenticates against the ${domainLabel} LDAP federation. In production, SPNEGO supplies the identity and no password form is shown.</div>
    <form action="${url.loginAction}" method="post">
      <div class="form-group"><label for="username">Windows user</label>
        <input id="username" name="username" class="form-control" value="PRV-PML" autofocus autocomplete="username" />
      </div>
      <div class="form-group"><label for="password">PoC password</label>
        <input id="password" name="password" class="form-control" type="password" autocomplete="current-password" />
      </div>
      <button class="pf-c-button pf-m-primary pf-m-block btn-lg" type="submit">Continue as Domain ${domainCode} user</button>
    </form>
  </#if>
</@layout.registrationLayout>
