<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
  <#if section = "header">Link a directory account
  <#elseif section = "form">
    <div class="poc-note">UEM requires at least one linked directory account before upload. Select the domain to validate against. The password is never stored.</div>
    <form action="${url.loginAction}" method="post">
      <div class="form-group"><label for="domain">Directory domain</label>
        <select id="domain" name="domain" class="form-control" autofocus>
          <#list directoryDomains as domain>
            <option value="${domain.code}">${domain.label} — ${domain.dnsName}</option>
          </#list>
        </select>
      </div>
      <div class="form-group"><label for="username">Directory user</label>
        <input id="username" name="username" class="form-control" autocomplete="username" required />
      </div>
      <div class="form-group"><label for="password">Directory password</label>
        <input id="password" name="password" class="form-control" type="password" autocomplete="current-password" required />
      </div>
      <button class="pf-c-button pf-m-primary pf-m-block btn-lg" type="submit">Verify and link account</button>
    </form>
  </#if>
</@layout.registrationLayout>
