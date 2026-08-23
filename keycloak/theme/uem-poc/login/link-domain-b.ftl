<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
  <#if section = "header">Link your Domain B identity
  <#elseif section = "form">
    <div class="poc-note">UEM requires a linked Domain B account before upload. The password is verified by a live LDAP bind and is never stored.</div>
    <form action="${url.loginAction}" method="post">
      <div class="form-group"><label for="b_username">Domain B user</label>
        <input id="b_username" name="b_username" class="form-control" value="PRV-PML" autofocus autocomplete="username" />
      </div>
      <div class="form-group"><label for="b_password">Domain B password</label>
        <input id="b_password" name="b_password" class="form-control" type="password" autocomplete="current-password" />
      </div>
      <button class="pf-c-button pf-m-primary pf-m-block btn-lg" type="submit">Verify and create 1:1 link</button>
    </form>
  </#if>
</@layout.registrationLayout>
