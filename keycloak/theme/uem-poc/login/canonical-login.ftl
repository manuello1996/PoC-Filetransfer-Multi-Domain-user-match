<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
  <#if section = "header">${domainLabel} workstation
  <#elseif section = "form">
    <div class="poc-note">This form simulates the Windows identity that SPNEGO would supply from a domain-joined workstation.</div>
    <form action="${url.loginAction}" method="post">
      <div class="form-group"><label for="username">Windows user</label>
        <input id="username" name="username" class="form-control" autocomplete="username" autofocus required />
      </div>
      <button class="pf-c-button pf-m-primary pf-m-block btn-lg" type="submit">Continue as ${domainLabel} user</button>
    </form>
  </#if>
</@layout.registrationLayout>
