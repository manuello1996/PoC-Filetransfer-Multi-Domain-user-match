<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
  <#if section = "header">Remove Domain ${domainCode} link
  <#elseif section = "form">
    <div class="poc-note">Remove the link to <strong>${linkedAccount}</strong> in Domain ${domainCode}. At least one other directory account must remain linked.</div>
    <form action="${url.loginAction}" method="post">
      <button class="pf-c-button pf-m-danger pf-m-block btn-lg" type="submit">Confirm removal</button>
    </form>
  </#if>
</@layout.registrationLayout>
