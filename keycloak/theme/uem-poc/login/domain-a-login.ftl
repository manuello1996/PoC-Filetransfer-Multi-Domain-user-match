<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
  <#if section = "header">Domain A workstation
  <#elseif section = "form">
    <div class="poc-note">This form simulates the Windows identity that SPNEGO would supply from a domain-joined workstation.</div>
    <form action="${url.loginAction}" method="post">
      <div class="form-group"><label for="a_username">Windows user</label>
        <input id="a_username" name="a_username" class="form-control" value="U12345" autofocus />
      </div>
      <button class="pf-c-button pf-m-primary pf-m-block btn-lg" type="submit">Continue as Domain A user</button>
    </form>
  </#if>
</@layout.registrationLayout>
