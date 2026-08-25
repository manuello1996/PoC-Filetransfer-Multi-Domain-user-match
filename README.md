# UEM Secure Transfer — local Windows PoC

This repository turns the accompanying solution design into a runnable identity-linking and file-segregation proof of concept. It uses Docker Desktop and works on a Windows PC that is **not** joined to Active Directory.

## Run it

Prerequisites: Docker Desktop using Linux containers.

```powershell
.\scripts\bootstrap.ps1 -Reset
```

The first run of this configuration model uses `-Reset` to replace any realm created by an older version of the PoC. It deletes all PoC volumes, identity links, and uploaded files. Later runs can use `.\scripts\bootstrap.ps1` without `-Reset`. A plain `docker compose up --build` remains useful after configuration has already been generated.

## Manage domains from one file

[`config/domains.json`](config/domains.json) is the source of truth for the canonical workstation domain and every LDAP/VDI directory domain. It contains the domain code, display and DNS names, host port, OIDC client, LDAP connection settings, LDIF seed file, and PoC test account. The canonical domain's `storage` section also defines the dedicated UEM metadata database and S3-compatible object store.

After adding, changing, or removing a directory entry, run:

```powershell
python .\scripts\generate-domain-config.py
docker compose up --build -d
```

Keycloak startup import creates a realm only when it does not already exist. Therefore, after changing the generated client/flow topology in this local PoC, copy anything needed and run `.\scripts\bootstrap.ps1 -Reset`. Ordinary rebuilds that do not change domain topology do not require a reset.

The generator validates unique codes, ports, and client IDs, checks that every referenced LDIF exists, and derives:

- `docker-compose.yml`, including the logical network zones, one LDAP container and one VDI app per directory domain, a UEM PostgreSQL instance, and a Garage object store;
- `keycloak/realm/uem-realm.json`, including clients, browser flows, redirects, and OIDC linkage claims;
- `keycloak/configure/generated-federations/*.json`, `user-profile.json`, and the restricted Domain A proxy configuration.

Treat those generated files as build artifacts: edit `domains.json`, not the repeated values in their output. To add Domain D, copy one object in `directoryDomains`, choose a unique code/port/client, add its LDIF under `ldap/bootstrap`, and run the bootstrap command. No Java or Flask change is required.

Wait until Keycloak reports that it has started. The three simulated computers have separate entry points:

| Simulated computer | URL | Allowed login |
|---|---|---|
| Domain A workstation | <http://localhost:8081> | Domain A login and directory-link settings |
| Domain B VDI | <http://localhost:8082> | Domain B only |
| Domain C VDI | <http://localhost:8083> | Domain C only |

The `keycloak-config` container is a one-shot initializer; an `Exited (0)` status for that container is expected.

Test credentials:

| Identity | Value |
|---|---|
| Simulated Domain A Windows user | Any value matching `[A-Za-z0-9._-]{1,64}` |
| Domain B LDAP user 1 | `USER-PML` / `DomainB-Poc-Password1!` |
| Domain B LDAP user 2 | `PRV-ALT` / `DomainB-Alt-Password1!` |
| Domain C LDAP user 1 | `USER-PML` / `DomainC-Poc-Password1!` |
| Domain C LDAP user 2 | `PRV-ALT` / `DomainC-Alt-Password1!` |
| Keycloak administrator | `admin` / `admin-poc-only` |

Suggested acceptance test:

1. Enter through **Domain A workstation** with any simulated username, for example `ALICE77`.
2. Keycloak immediately presents the default required action **Link a directory account**. UEM is not opened yet.
3. Choose Domain B or Domain C and supply a valid credential from that directory. The custom flow targets the selected Keycloak User Federation provider, resolves `sAMAccountName`, and validates the password in LDAP.
4. After successful linking, Keycloak completes the login and opens UEM.
5. UEM returns with `link_status=ACTIVE`, displays the linked account, and enables upload.
6. Open **Settings** to add an account from the other directory. A link can be removed only while another active link remains.
7. Sign in through the corresponding VDI at <http://localhost:8082> or <http://localhost:8083>. Every linked path resolves to the same Keycloak subject and file space.
8. An incorrect directory password creates no link and grants no upload access.
9. Delete a file from any entry point and confirm it disappears everywhere. Delete requests are POST-only, CSRF-protected, and constrained to the authenticated canonical owner.

Run the automated version with arbitrary test identities:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke-test.ps1
```

The test links B and C, exercises both VDIs, removes B, verifies C remains, and deletes its generated canonical account afterward. Add `-KeepTestUser` only when you intentionally want to inspect the resulting account and linkage in Keycloak.

## Logical network simulation

Compose models the intended trust zones even though all published `localhost` ports remain reachable from the Windows host:

- `unsecure-domain-a` contains the Domain A application and the Domain A side of `domain-a-auth-proxy`. The application has no Docker route or DNS entry for `keycloak`.
- `service-inout` contains Keycloak, its database, LDAP services, and the trusted side of the Domain A authentication proxy.
- each VDI has its own `vdi-domain-<code>` network and can reach Keycloak directly;
- `uem-data` contains the UEM metadata database and Garage object store.

Domain A redirects the browser only to the restricted proxy at <http://localhost:8180/domain-a>. It exposes the configured `uem` realm authentication paths and login-theme resources, while `/admin` and every unrelated path return 404. The Domain A backend also performs token and session operations through this proxy. It never connects directly to the `keycloak` Docker service.

VDI applications use Keycloak directly at <http://localhost:8080>. The Keycloak Admin Console is therefore available from the simulated VDI side at <http://localhost:8080/admin/master/console/> with `admin` / `admin-poc-only`. In realm `uem`, open **User federation** to inspect the generated LDAP providers. Open **Users**, select the generated `uem-...` canonical account, and inspect **UEM identity linkage**.

This is a logical topology demonstration, not a host firewall. In production, publish each endpoint only in its actual network zone, use DNS names and HTTPS, and enforce the boundary with routing and firewall rules. The Domain A browser still participates in OIDC, but all Keycloak pages and protocol requests are carried through the restricted proxy; the browser never connects to Keycloak directly.

To inspect the simulated Domain B directory directly (replace `b` with `c` for Domain C):

```powershell
docker compose exec domain-b-ldap ldapsearch -x `
  -H ldap://localhost:389 `
  -D "cn=admin,dc=b,dc=consoto,dc=com" `
  -w "ldap-admin-poc-only" `
  -b "ou=people,dc=b,dc=consoto,dc=com" `
  "(objectClass=inetOrgPerson)" uid sAMAccountName dn cn mail
```

To reset all PoC state, including the link and uploaded files:

```powershell
docker compose down -v
```

This permanently removes the LDAP, both PostgreSQL, and Garage data volumes used by this project.

## What is simulated

The custom Keycloak authenticators replace only the infrastructure unavailable on a standalone PC:

- Domain A's form represents the principal normally obtained from Kerberos/SPNEGO. It intentionally asks for no Domain A password.
- Domains B and C are separate OpenLDAP containers seeded from domain-specific LDIF files. They deliberately contain the same `sAMAccountName` values to prove domain-qualified linking. The initializer creates a read-only, non-importing User Federation for each directory. The custom flow targets the selected federation component, so duplicate usernames across domains remain unambiguous. Passwords are not stored by Keycloak or UEM.
- The visible B/C login forms replace only the Kerberos/SPNEGO part that domain-joined VDIs would normally perform transparently.

The important design properties are implemented rather than mocked: Domain A creates or reuses one canonical Keycloak account; at least one B/C link is mandatory before the first authorization code is issued; each directory account is 1:1 within its own domain; and every linked path emits the same stable `sub`. Upload requires `link_status=ACTIVE` and at least one domain-specific identity claim. The final link cannot be removed until another one is added.

Each UEM logout is scoped to the application where it was initiated. Keycloak removes only that authenticated client session (`uem-a`, `uem-b`, or `uem-c`) from the parent SSO session; other applications remain signed in. Temporary link-management client sessions are revoked immediately while the original Domain A client session is preserved. The UEM instances use different cookie names while sharing canonical identities through the dedicated UEM metadata database and S3 object namespace—there is no filesystem volume mounted into multiple application containers.

Removing a directory link terminates every authenticated Keycloak client session for that user and domain (`uem-b` or `uem-c`) across all parent SSO sessions. It does not terminate the Domain A client or sessions for other linked domains. Every authenticated UEM page runs a background check against `/session/status` every 30 seconds. The endpoint introspects the server-held refresh token with Keycloak; valid pages are not reloaded, while an invalid or revoked client session clears the local session and redirects the browser to that instance's entry page.

## Production Windows SSO direction

For Microsoft Active Directory, configure **LDAP User Federation with Vendor = Active Directory** for directory lookup, attributes, lifecycle synchronization, and optional password validation. Set the username LDAP attribute to `sAMAccountName`, the RDN attribute as required by your directory layout, and the stable UUID attribute to `objectGUID`. Prefer `READ_ONLY`, LDAPS, a least-privilege bind account, and secret injection from a vault.

Windows-session SSO additionally requires **Kerberos/SPNEGO**. Enable **Allow Kerberos authentication** on the LDAP federation provider, configure the AD Kerberos realm, `HTTP/<keycloak-host>` service principal and protected keytab, then add the **Kerberos** execution to the browser authentication flow. Configure DNS, `/etc/krb5.conf`, HTTPS, SPNs, and managed-browser intranet/Negotiate allowlists for both entry hostnames.

Do not expect multiple LDAP federation providers to merge users automatically. Keep a governed, domain-qualified canonical-link layer—such as the custom SPI demonstrated here—or use a central identity/broker architecture that emits one immutable subject. Store each link using `domain + objectGUID`; use `sAMAccountName` only as the human login name because it can be renamed or reused.

## File retention and deletion

Users can download or permanently delete their own files from the **Stored files** table. The server resolves every delete by both the opaque file ID and the authenticated Keycloak `sub`; knowing another file ID is not sufficient. Delete requests require the CSRF token held in that web session.

File bytes are stored in the private `uem-uploads` bucket in the `uem-object-storage` Garage container. File ownership, hashes, names, timestamps, and server-held OIDC refresh tokens are stored in the separate `uem-metadata-db` PostgreSQL instance. Keycloak continues to use its own independent `postgres` service.

The Garage S3 API is available at <http://localhost:9000>. Garage has no built-in web console; its authenticated administration API is exposed locally at <http://localhost:3903>. The fixed S3 access key and secret in `config/domains.json` are for the local PoC only.

The dedicated `uem-cleanup` container starts cleanup every day at **23:59 Europe/Zurich** and removes eligible S3 objects followed by their PostgreSQL metadata records. A final sweep at midnight catches uploads made during the last minute, and older records are also removed if a previous cleanup was missed. To exercise the same cleanup immediately:

```powershell
docker compose exec uem-cleanup python cleanup.py --run-once
```

The UEM pages use the same dark neutral, emerald-accented design language as the local OPC application. The project-specific stylesheet is [`uem/static/uem.css`](uem/static/uem.css); the Keycloak theme is unchanged.

This is not production-ready. It deliberately uses HTTP, development-mode Keycloak, fixed local secrets, local SQLite/filesystem storage, and no malware scanner, SIEM, rate limiter, TLS, AD, or Kerberos.
