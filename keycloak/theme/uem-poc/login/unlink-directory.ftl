<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
  <#if section = "header">Remove a directory link
  <#elseif section = "form">
    <div class="poc-note">Select a linked account to remove. Its domain client sessions will be terminated. At least one other directory account must remain linked.</div>
    <form action="${url.loginAction}" method="post">
      <div class="form-group"><label for="domain">Linked directory account</label>
        <select id="domain" name="domain" class="form-control" autofocus>
          <#list linkedAccounts as linked>
            <option value="${linked.code}">${linked.label} — ${linked.account}</option>
          </#list>
        </select>
      </div>
      <button class="pf-c-button pf-m-danger pf-m-block btn-lg" type="submit">Remove selected link</button>
    </form>
  </#if>
</@layout.registrationLayout>
