param(
    [string]$DomainAUser = 'MULTI-DOMAIN-SMOKE',
    [string]$ConfigPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'config/domains.json'),
    [switch]$KeepTestUser
)

$ErrorActionPreference = 'Stop'
$domainConfig = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if ($domainConfig.directoryDomains.Count -lt 2) { throw 'The full smoke test requires at least two configured directory domains.' }
$canonical = $domainConfig.canonicalDomain
$primary = $domainConfig.directoryDomains[0]
$secondary = $domainConfig.directoryDomains[1]
$DirectoryUser = $primary.testAccount.username
if ($secondary.testAccount.username -ne $DirectoryUser) { throw 'The first two domains must share the configured smoke-test username.' }
$cookieJar = [IO.Path]::GetTempFileName()
$domainASub = $null
$smokeSucceeded = $false

function Invoke-CurlPage {
    param([string[]]$Arguments)
    $content = (& curl.exe @Arguments) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "curl failed with exit code $LASTEXITCODE" }
    return $content
}

function Get-FormAction {
    param([string]$Html)
    $value = [regex]::Match($Html, '<form action="([^"]+)"').Groups[1].Value
    if (-not $value) { throw 'No HTML form action was found.' }
    return [Net.WebUtility]::HtmlDecode($value)
}

function Invoke-VdiLogin {
    param($Domain)
    $form = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        "http://localhost:$($Domain.port)/login/$($Domain.code)")
    if ($form -notmatch [regex]::Escape("$($Domain.label) VDI")) { throw "$($Domain.label) login form was not rendered." }
    return Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', "username=$DirectoryUser",
        '--data-urlencode', "password=$($Domain.testAccount.password)", (Get-FormAction $form))
}

try {
    $domainAForm = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        "http://localhost:$($canonical.port)/login/$($canonical.code)")
    $linkForm = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', "username=$DomainAUser", (Get-FormAction $domainAForm))
    "DEFAULT_LINK_REQUIRED=$($linkForm -match 'Link a directory account')"
    "DOMAIN_DROPDOWN=$($linkForm -match [regex]::Escape($primary.dnsName) -and $linkForm -match [regex]::Escape($secondary.dnsName))"
    if ($linkForm -notmatch 'Link a directory account' -or $linkForm -notmatch [regex]::Escape($secondary.dnsName)) {
        throw 'The multi-domain first-login required action was not rendered.'
    }

    $domainAResult = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', "domain=$($primary.code)",
        '--data-urlencode', "username=$DirectoryUser",
        '--data-urlencode', "password=$($primary.testAccount.password)", (Get-FormAction $linkForm))
    "INITIAL_DIRECTORY_LINK=$($domainAResult -match "$($primary.code.ToUpper()):$([regex]::Escape($DirectoryUser))")"
    "UPLOAD_ENABLED=$($domainAResult -match '>Upload file</button>')"
    $heartbeatPresent = $domainAResult -match "fetch\('/session/status'" -and $domainAResult -match '30000'
    "SESSION_HEARTBEAT_PRESENT=$heartbeatPresent"
    if ($domainAResult -notmatch "$($primary.code.ToUpper()):$([regex]::Escape($DirectoryUser))" -or $domainAResult -notmatch '>Upload file</button>') {
        throw 'Initial directory linking did not open the file application.'
    }
    $domainASub = [regex]::Match($domainAResult, 'KEYCLOAK SUBJECT</span><code>([^<]+)').Groups[1].Value

    $settingsBefore = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        "http://localhost:$($canonical.port)/settings")
    "SETTINGS_SHOW_PRIMARY=$($settingsBefore -match "(?s)$([regex]::Escape($primary.label.ToUpper()))</span>.*?$([regex]::Escape($DirectoryUser))")"
    "SETTINGS_SHOW_SECONDARY_UNLINKED=$($settingsBefore -match "(?s)$([regex]::Escape($secondary.label.ToUpper()))</span>.*?Not linked")"
    "LAST_LINK_PROTECTED=$($settingsBefore -match 'Required while it is the only link')"

    $addCForm = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        "http://localhost:$($canonical.port)/login/link")
    $settingsWithBoth = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', "domain=$($secondary.code)",
        '--data-urlencode', "username=$DirectoryUser",
        '--data-urlencode', "password=$($secondary.testAccount.password)", (Get-FormAction $addCForm))
    "SECONDARY_LINK_ADDED=$($settingsWithBoth -match "(?s)$([regex]::Escape($secondary.label.ToUpper()))</span>.*?$([regex]::Escape($DirectoryUser))")"
    "BOTH_LINKS_REMOVABLE=$(([regex]::Matches($settingsWithBoth, 'Remove link')).Count -eq 2)"
    if ($settingsWithBoth -notmatch "(?s)$([regex]::Escape($secondary.label.ToUpper()))</span>.*?$([regex]::Escape($DirectoryUser))" -or
        ([regex]::Matches($settingsWithBoth, 'Remove link')).Count -ne 2) {
        throw 'The second domain link was not reflected in settings.'
    }

    $uploadResult = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '-F', 'file=@README.md', "http://localhost:$($canonical.port)/files")
    "DOMAIN_A_UPLOAD=$($uploadResult -match '>README.md<')"

    $domainBResult = Invoke-VdiLogin -Domain $primary
    $domainBSub = [regex]::Match($domainBResult, 'KEYCLOAK SUBJECT</span><code>([^<]+)').Groups[1].Value
    "DOMAIN_B_SAME_SUB=$($domainBSub -eq $domainASub -and $domainASub.Length -gt 0)"
    "DOMAIN_B_SHARED_FILE=$($domainBResult -match '>README.md<')"

    $domainCResult = Invoke-VdiLogin -Domain $secondary
    $domainCSub = [regex]::Match($domainCResult, 'KEYCLOAK SUBJECT</span><code>([^<]+)').Groups[1].Value
    "DOMAIN_C_SAME_SUB=$($domainCSub -eq $domainASub -and $domainASub.Length -gt 0)"
    "DOMAIN_C_SHARED_FILE=$($domainCResult -match '>README.md<')"
    if ($domainBSub -ne $domainASub -or $domainCSub -ne $domainASub) {
        throw 'A, B, and C did not resolve to the same canonical subject.'
    }

    $unlinkBForm = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        "http://localhost:$($canonical.port)/login/unlink")
    if ($unlinkBForm -notmatch 'Remove a directory link') { throw 'Directory unlink form was not rendered.' }
    $settingsAfterRemove = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', "domain=$($primary.code)", (Get-FormAction $unlinkBForm))
    "PRIMARY_LINK_REMOVED=$($settingsAfterRemove -match "(?s)$([regex]::Escape($primary.label.ToUpper()))</span>.*?Not linked")"
    "SECONDARY_LINK_REMAINS=$($settingsAfterRemove -match "(?s)$([regex]::Escape($secondary.label.ToUpper()))</span>.*?$([regex]::Escape($DirectoryUser))")"
    "NEW_LAST_LINK_PROTECTED=$($settingsAfterRemove -match 'Required while it is the only link')"

    & docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh config credentials `
        --server http://localhost:8080 --realm master --user admin --password admin-poc-only | Out-Null
    $sessionsAfterUnlink = (& docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh get "users/$domainASub/sessions" -r $domainConfig.realm.name) -join "`n"
    "UNLINK_TERMINATED_PRIMARY_CLIENT=$($sessionsAfterUnlink -notmatch [regex]::Escape($primary.clientId))"
    "UNLINK_PRESERVED_CANONICAL_CLIENT=$($sessionsAfterUnlink -match [regex]::Escape($canonical.clientId))"
    "UNLINK_PRESERVED_SECONDARY_CLIENT=$($sessionsAfterUnlink -match [regex]::Escape($secondary.clientId))"
    if ($sessionsAfterUnlink -match [regex]::Escape($primary.clientId) -or $sessionsAfterUnlink -notmatch [regex]::Escape($canonical.clientId) -or $sessionsAfterUnlink -notmatch [regex]::Escape($secondary.clientId)) {
        throw 'Directory unlink did not terminate only the selected domain client sessions.'
    }

    $bHeartbeatStatus = (& curl.exe -sS -o NUL -w '%{http_code}' -c $cookieJar -b $cookieJar `
        "http://localhost:$($primary.port)/session/status") -join ''
    "B_HEARTBEAT_DETECTS_TERMINATION=$($bHeartbeatStatus -eq '401')"
    if ($bHeartbeatStatus -ne '401') { throw "Removed-domain heartbeat returned HTTP $bHeartbeatStatus instead of 401." }

    $failedBLogin = Invoke-VdiLogin -Domain $primary
    "REMOVED_PRIMARY_LOGIN_REJECTED=$($failedBLogin -match [regex]::Escape("No $($primary.label) link exists"))"
    if ($failedBLogin -notmatch [regex]::Escape("No $($primary.label) link exists")) { throw 'Removed primary directory link could still start a new VDI session.' }

    $deleteMatch = [regex]::Match($domainCResult, "(?s)<form method=post action='(/files/[^']+/delete)'.*?name=csrf_token value='([^']+)'")
    if (-not $deleteMatch.Success) { throw 'No CSRF-protected delete action was rendered.' }
    $deleteResult = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', "csrf_token=$($deleteMatch.Groups[2].Value)",
        "http://localhost:$($secondary.port)$($deleteMatch.Groups[1].Value)")
    "DOMAIN_C_OWNER_DELETE=$($deleteResult -notmatch '>README.md<')"

    Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar, "http://localhost:$($secondary.port)/logout") | Out-Null
    $sessions = (& docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh get "users/$domainASub/sessions" -r $domainConfig.realm.name) -join "`n"
    "CANONICAL_CLIENT_PRESERVED=$($sessions -match [regex]::Escape($canonical.clientId))"
    "TEMP_LINK_CLIENT_CLOSED=$($sessions -notmatch 'uem-link')"
    if ($sessions -notmatch [regex]::Escape($canonical.clientId) -or $sessions -match [regex]::Escape($domainConfig.linkClient.clientId)) {
        throw 'Link management did not preserve only the original Domain A client session.'
    }
    Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar, "http://localhost:$($canonical.port)/logout") | Out-Null
    $smokeSucceeded = $true
}
finally {
    Remove-Item -LiteralPath $cookieJar -Force -ErrorAction SilentlyContinue
    if ($smokeSucceeded -and $domainASub -and -not $KeepTestUser) {
        & docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh config credentials `
            --server http://localhost:8080 --realm master --user admin --password admin-poc-only | Out-Null
        & docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh delete "users/$domainASub" -r $domainConfig.realm.name
        "TEST_USER_CLEANUP=$($LASTEXITCODE -eq 0)"
    }
}
