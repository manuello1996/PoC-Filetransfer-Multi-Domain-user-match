param(
    [string]$DomainAUser = 'MULTI-DOMAIN-SMOKE',
    [string]$DirectoryUser = 'PRV-ALT',
    [string]$DomainBPassword = 'DomainB-Alt-Password1!',
    [string]$DomainCPassword = 'DomainC-Alt-Password1!',
    [switch]$KeepTestUser
)

$ErrorActionPreference = 'Stop'
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
    param([string]$Domain, [int]$Port, [string]$Password)
    $form = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        "http://localhost:$Port/login/$($Domain.ToLower())")
    if ($form -notmatch "Domain $Domain VDI") { throw "Domain $Domain login form was not rendered." }
    return Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', "username=$DirectoryUser",
        '--data-urlencode', "password=$Password", (Get-FormAction $form))
}

try {
    $domainAForm = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        'http://localhost:8081/login/a')
    $linkForm = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', "a_username=$DomainAUser", (Get-FormAction $domainAForm))
    "DEFAULT_LINK_REQUIRED=$($linkForm -match 'Link a directory account')"
    "DOMAIN_DROPDOWN=$($linkForm -match 'b.consoto.com' -and $linkForm -match 'c.consoto.com')"
    if ($linkForm -notmatch 'Link a directory account' -or $linkForm -notmatch 'c.consoto.com') {
        throw 'The multi-domain first-login required action was not rendered.'
    }

    $domainAResult = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', 'domain=b',
        '--data-urlencode', "username=$DirectoryUser",
        '--data-urlencode', "password=$DomainBPassword", (Get-FormAction $linkForm))
    "INITIAL_DOMAIN_B_LINK=$($domainAResult -match "B:$([regex]::Escape($DirectoryUser))")"
    "UPLOAD_ENABLED=$($domainAResult -match '>Upload file</button>')"
    $heartbeatPresent = $domainAResult -match "fetch\('/session/status'" -and $domainAResult -match '30000'
    "SESSION_HEARTBEAT_PRESENT=$heartbeatPresent"
    if ($domainAResult -notmatch "B:$([regex]::Escape($DirectoryUser))" -or $domainAResult -notmatch '>Upload file</button>') {
        throw 'Initial Domain B linking did not open the file application.'
    }
    $domainASub = [regex]::Match($domainAResult, 'KEYCLOAK SUBJECT</span><code>([^<]+)').Groups[1].Value

    $settingsBefore = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        'http://localhost:8081/settings')
    "SETTINGS_SHOW_B=$($settingsBefore -match "(?s)DOMAIN B</span>.*?$([regex]::Escape($DirectoryUser))")"
    "SETTINGS_SHOW_C_UNLINKED=$($settingsBefore -match '(?s)DOMAIN C</span>.*?Not linked')"
    "LAST_LINK_PROTECTED=$($settingsBefore -match 'Required while it is the only link')"

    $addCForm = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        'http://localhost:8081/login/link')
    $settingsWithBoth = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', 'domain=c',
        '--data-urlencode', "username=$DirectoryUser",
        '--data-urlencode', "password=$DomainCPassword", (Get-FormAction $addCForm))
    "DOMAIN_C_LINK_ADDED=$($settingsWithBoth -match "(?s)DOMAIN C</span>.*?$([regex]::Escape($DirectoryUser))")"
    "BOTH_LINKS_REMOVABLE=$(([regex]::Matches($settingsWithBoth, 'Remove link')).Count -eq 2)"
    if ($settingsWithBoth -notmatch "(?s)DOMAIN C</span>.*?$([regex]::Escape($DirectoryUser))" -or
        ([regex]::Matches($settingsWithBoth, 'Remove link')).Count -ne 2) {
        throw 'The second domain link was not reflected in settings.'
    }

    $uploadResult = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '-F', 'file=@README.md', 'http://localhost:8081/files')
    "DOMAIN_A_UPLOAD=$($uploadResult -match '>README.md<')"

    $domainBResult = Invoke-VdiLogin -Domain B -Port 8082 -Password $DomainBPassword
    $domainBSub = [regex]::Match($domainBResult, 'KEYCLOAK SUBJECT</span><code>([^<]+)').Groups[1].Value
    "DOMAIN_B_SAME_SUB=$($domainBSub -eq $domainASub -and $domainASub.Length -gt 0)"
    "DOMAIN_B_SHARED_FILE=$($domainBResult -match '>README.md<')"

    $domainCResult = Invoke-VdiLogin -Domain C -Port 8083 -Password $DomainCPassword
    $domainCSub = [regex]::Match($domainCResult, 'KEYCLOAK SUBJECT</span><code>([^<]+)').Groups[1].Value
    "DOMAIN_C_SAME_SUB=$($domainCSub -eq $domainASub -and $domainASub.Length -gt 0)"
    "DOMAIN_C_SHARED_FILE=$($domainCResult -match '>README.md<')"
    if ($domainBSub -ne $domainASub -or $domainCSub -ne $domainASub) {
        throw 'A, B, and C did not resolve to the same canonical subject.'
    }

    $unlinkBForm = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        'http://localhost:8081/login/unlink-b')
    if ($unlinkBForm -notmatch 'Remove Domain B link') { throw 'Domain B unlink confirmation was not rendered.' }
    $settingsAfterRemove = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        (Get-FormAction $unlinkBForm))
    "DOMAIN_B_LINK_REMOVED=$($settingsAfterRemove -match '(?s)DOMAIN B</span>.*?Not linked')"
    "DOMAIN_C_LINK_REMAINS=$($settingsAfterRemove -match "(?s)DOMAIN C</span>.*?$([regex]::Escape($DirectoryUser))")"
    "NEW_LAST_LINK_PROTECTED=$($settingsAfterRemove -match 'Required while it is the only link')"

    & docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh config credentials `
        --server http://localhost:8080 --realm master --user admin --password admin-poc-only | Out-Null
    $sessionsAfterUnlink = (& docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh get "users/$domainASub/sessions" -r uem) -join "`n"
    "UNLINK_TERMINATED_B_CLIENT=$($sessionsAfterUnlink -notmatch 'uem-b')"
    "UNLINK_PRESERVED_A_CLIENT=$($sessionsAfterUnlink -match 'uem-a')"
    "UNLINK_PRESERVED_C_CLIENT=$($sessionsAfterUnlink -match 'uem-c')"
    if ($sessionsAfterUnlink -match 'uem-b' -or $sessionsAfterUnlink -notmatch 'uem-a' -or $sessionsAfterUnlink -notmatch 'uem-c') {
        throw 'Domain B unlink did not terminate only the Domain B client sessions.'
    }

    $bHeartbeatStatus = (& curl.exe -sS -o NUL -w '%{http_code}' -c $cookieJar -b $cookieJar `
        'http://localhost:8082/session/status') -join ''
    "B_HEARTBEAT_DETECTS_TERMINATION=$($bHeartbeatStatus -eq '401')"
    if ($bHeartbeatStatus -ne '401') { throw "Domain B heartbeat returned HTTP $bHeartbeatStatus instead of 401." }

    $failedBLogin = Invoke-VdiLogin -Domain B -Port 8082 -Password $DomainBPassword
    "REMOVED_B_LOGIN_REJECTED=$($failedBLogin -match 'No Domain B link exists')"
    if ($failedBLogin -notmatch 'No Domain B link exists') { throw 'Removed Domain B link could still start a new VDI session.' }

    $deleteMatch = [regex]::Match($domainCResult, "(?s)<form method=post action='(/files/[^']+/delete)'.*?name=csrf_token value='([^']+)'")
    if (-not $deleteMatch.Success) { throw 'No CSRF-protected delete action was rendered.' }
    $deleteResult = Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar,
        '--data-urlencode', "csrf_token=$($deleteMatch.Groups[2].Value)",
        "http://localhost:8083$($deleteMatch.Groups[1].Value)")
    "DOMAIN_C_OWNER_DELETE=$($deleteResult -notmatch '>README.md<')"

    Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar, 'http://localhost:8083/logout') | Out-Null
    $sessions = (& docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh get "users/$domainASub/sessions" -r uem) -join "`n"
    "DOMAIN_A_CLIENT_PRESERVED=$($sessions -match 'uem-a')"
    "TEMP_LINK_CLIENT_CLOSED=$($sessions -notmatch 'uem-link')"
    if ($sessions -notmatch 'uem-a' -or $sessions -match 'uem-link') {
        throw 'Link management did not preserve only the original Domain A client session.'
    }
    Invoke-CurlPage @('-sS', '-L', '-c', $cookieJar, '-b', $cookieJar, 'http://localhost:8081/logout') | Out-Null
    $smokeSucceeded = $true
}
finally {
    Remove-Item -LiteralPath $cookieJar -Force -ErrorAction SilentlyContinue
    if ($smokeSucceeded -and $domainASub -and -not $KeepTestUser) {
        & docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh config credentials `
            --server http://localhost:8080 --realm master --user admin --password admin-poc-only | Out-Null
        & docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh delete "users/$domainASub" -r uem
        "TEST_USER_CLEANUP=$($LASTEXITCODE -eq 0)"
    }
}
