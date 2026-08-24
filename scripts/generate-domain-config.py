"""Generate all domain-dependent PoC configuration from config/domains.json."""

from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "config" / "domains.json"
FEDERATION_DIR = ROOT / "keycloak" / "configure" / "generated-federations"
DOMAIN_A_PROXY_CONFIG = ROOT / "keycloak" / "domain-a-proxy" / "generated-nginx.conf"


def fail(message: str) -> None:
    raise SystemExit(f"Domain configuration error: {message}")


def load_config() -> dict:
    config = json.loads(SOURCE.read_text(encoding="utf-8"))
    domains = [config["canonicalDomain"], *config["directoryDomains"]]
    storage = config["canonicalDomain"]["storage"]
    realm = config["realm"]
    codes = [domain["code"] for domain in domains]
    ports = [domain["port"] for domain in domains]
    clients = [domain["clientId"] for domain in domains]
    if any(not re.fullmatch(r"[a-z][a-z0-9-]*", code) for code in codes):
        fail("domain codes must match [a-z][a-z0-9-]*")
    for label, values in (("domain code", codes), ("host port", ports), ("client ID", clients)):
        if len(values) != len(set(values)):
            fail(f"duplicate {label}")
    if not config["directoryDomains"]:
        fail("at least one directoryDomain is required")
    object_storage = storage["objectStorage"]
    if not re.fullmatch(r"GK[0-9a-fA-F]{32}", object_storage["accessKey"]):
        fail("Garage accessKey must be GK followed by 32 hexadecimal characters")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", object_storage["secretKey"]):
        fail("Garage secretKey must contain 64 hexadecimal characters")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", object_storage["rpcSecret"]):
        fail("Garage rpcSecret must contain 64 hexadecimal characters")
    infrastructure_ports = [realm["keycloakPort"], realm["domainAAuthProxy"]["port"], storage["objectStorage"]["apiPort"], storage["objectStorage"]["adminPort"]]
    if set(ports).intersection(infrastructure_ports) or len(infrastructure_ports) != len(set(infrastructure_ports)):
        fail("application, Keycloak, S3 API, and object-storage admin host ports must be unique")
    proxy_path = realm["domainAAuthProxy"]["path"]
    if not re.fullmatch(r"/[a-z][a-z0-9-]*", proxy_path):
        fail("domainAAuthProxy.path must be one simple absolute path segment")
    for domain in config["directoryDomains"]:
        ldap = domain["ldap"]
        expected = ROOT / "ldap" / "bootstrap" / ldap["usersLdif"]
        if not expected.is_file():
            fail(f"missing LDAP seed file {expected.relative_to(ROOT)}")
    return config


def stable_id(name: str) -> str:
    return str(uuid.uuid5(uuid.UUID("efad27a0-1447-4c35-8e67-1bf9c2ff91ed"), name))


def mapper(domain: dict) -> dict:
    code = domain["code"]
    return {
        "name": f"domain-{code}-identity",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": f"identity_{code}",
            "claim.name": f"domain_{code}_identity",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        },
    }


def link_status_mapper() -> dict:
    return {
        "name": "link-status",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": "link_status",
            "claim.name": "link_status",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
        },
    }


def generate_realm(config: dict) -> dict:
    canonical = config["canonicalDomain"]
    directories = config["directoryDomains"]
    all_mappers = [mapper(domain) for domain in directories] + [link_status_mapper()]
    flows = []
    clients = []

    canonical_flow = stable_id(f"flow:{canonical['code']}")
    flows.append({
        "id": canonical_flow, "alias": f"poc-domain-{canonical['code']}",
        "description": f"Simulated {canonical['label']} Windows SSO plus first-time directory linking",
        "providerId": "basic-flow", "topLevel": True, "builtIn": False,
        "authenticationExecutions": [{"authenticator": "uem-poc-canonical", "requirement": "REQUIRED", "priority": 10, "authenticatorFlow": False}],
    })
    manage_flow = stable_id("flow:manage-links")
    flows.append({
        "id": manage_flow, "alias": "poc-manage-links",
        "description": "Existing Keycloak SSO session required for self-service link management",
        "providerId": "basic-flow", "topLevel": True, "builtIn": False,
        "authenticationExecutions": [{"authenticator": "auth-cookie", "requirement": "REQUIRED", "priority": 10, "authenticatorFlow": False}],
    })

    def oidc_client(domain: dict, flow_id: str) -> dict:
        origin = f"http://localhost:{domain['port']}"
        return {
            "clientId": domain["clientId"], "name": f"UEM from {domain['label']}", "enabled": True,
            "attributes": {"uemDomainCode": domain["code"], "uemDomainLabel": domain["label"], "uemDomainDnsName": domain["dnsName"], "uemDomainType": "canonical" if domain is canonical else "directory"},
            "clientAuthenticatorType": "client-secret", "secret": domain["clientSecret"],
            "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "publicClient": False,
            "redirectUris": [f"{origin}/callback/{domain['code']}"], "webOrigins": [origin],
            "authenticationFlowBindingOverrides": {"browser": flow_id},
            "protocolMappers": all_mappers,
        }

    clients.append(oidc_client(canonical, canonical_flow))
    for domain in directories:
        flow_id = stable_id(f"flow:{domain['code']}")
        flows.append({
            "id": flow_id, "alias": f"poc-domain-{domain['code']}",
            "description": f"Simulated {domain['label']} Windows SSO",
            "providerId": "basic-flow", "topLevel": True, "builtIn": False,
            "authenticationExecutions": [{"authenticator": "uem-poc-directory", "requirement": "REQUIRED", "priority": 10, "authenticatorFlow": False}],
        })
        clients.append(oidc_client(domain, flow_id))

    canonical_origin = f"http://localhost:{canonical['port']}"
    link = config["linkClient"]
    clients.append({
        "clientId": link["clientId"], "name": "UEM self-service directory linking", "enabled": True,
        "clientAuthenticatorType": "client-secret", "secret": link["clientSecret"],
        "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "publicClient": False,
        "redirectUris": [f"{canonical_origin}/callback/link", f"{canonical_origin}/callback/unlink"],
        "webOrigins": [canonical_origin], "authenticationFlowBindingOverrides": {"browser": manage_flow},
        "protocolMappers": all_mappers,
    })
    return {
        "realm": config["realm"]["name"], "enabled": True, "displayName": config["realm"]["displayName"],
        "loginTheme": "uem-poc", "sslRequired": "none", "registrationAllowed": False,
        "resetPasswordAllowed": False, "rememberMe": False, "accessTokenLifespan": 300,
        "ssoSessionIdleTimeout": 1800,
        "requiredActions": [
            {"alias": "uem-link-directory", "name": "Link a directory account", "providerId": "uem-link-directory", "enabled": True, "defaultAction": True, "priority": 100},
            {"alias": "uem-unlink-directory", "name": "Unlink a directory account", "providerId": "uem-unlink-directory", "enabled": True, "defaultAction": False, "priority": 110},
        ],
        "authenticationFlows": flows, "clients": clients,
    }


def profile_attribute(name: str, display: str, user_visible: bool = False) -> dict:
    viewers = ["admin", "user"] if user_visible else ["admin"]
    return {"name": name, "displayName": display, "permissions": {"view": viewers, "edit": ["admin"]}, "group": "identity-linkage", "multivalued": False}


def generate_user_profile(config: dict) -> dict:
    attributes = [
        {"name": "username", "displayName": "${username}", "validations": {"length": {"min": 3, "max": 255}, "username-prohibited-characters": {}, "up-username-not-idn-homograph": {}}, "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]}, "multivalued": False},
        {"name": "email", "displayName": "${email}", "validations": {"email": {}, "length": {"max": 255}}, "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]}, "multivalued": False},
        {"name": "firstName", "displayName": "${firstName}", "validations": {"length": {"max": 255}, "person-name-prohibited-characters": {}}, "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]}, "multivalued": False},
        {"name": "lastName", "displayName": "${lastName}", "validations": {"length": {"max": 255}, "person-name-prohibited-characters": {}}, "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]}, "multivalued": False},
        profile_attribute(f"identity_{config['canonicalDomain']['code']}", f"Linked {config['canonicalDomain']['label']} principal", True),
    ]
    for domain in config["directoryDomains"]:
        code, label = domain["code"], domain["label"]
        attributes.extend([
            profile_attribute(f"identity_{code}", f"Linked {label} principal", True),
            profile_attribute(f"identity_{code}_id", f"{label} immutable directory ID"),
            profile_attribute(f"domain_{code}_dn", f"{label} LDAP DN"),
            profile_attribute(f"linked_{code}_at", f"{label} linked at (UTC)", True),
        ])
    attributes.extend([
        profile_attribute("link_status", "Link status", True),
        profile_attribute("linked_at", "Linked at (UTC)", True),
        profile_attribute("link_method", "Link method"),
    ])
    return {"attributes": attributes, "groups": [{"name": "identity-linkage", "displayHeader": "UEM identity linkage", "displayDescription": "Read-only linkage established by the UEM self-service authentication flow."}]}


def generate_federations(config: dict) -> None:
    FEDERATION_DIR.mkdir(parents=True, exist_ok=True)
    for old in FEDERATION_DIR.glob("*.json"):
        old.unlink()
    for priority, domain in enumerate(config["directoryDomains"]):
        code, ldap = domain["code"], domain["ldap"]
        federation = {
            "name": f"domain-{code}-ldap-poc", "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider", "parentId": "@@REALM_ID@@",
            "config": {
                "enabled": ["true"], "priority": [str(priority)], "editMode": ["READ_ONLY"],
                "importEnabled": ["false"], "syncRegistrations": ["false"], "vendor": ["other"],
                "usernameLDAPAttribute": [ldap["usernameAttribute"]], "rdnLDAPAttribute": [ldap["rdnAttribute"]],
                "uuidLDAPAttribute": [ldap["uuidAttribute"]], "userObjectClasses": [ldap["objectClasses"]],
                "connectionUrl": [f"ldap://{ldap['service']}:389"], "usersDn": [ldap["usersDn"]],
                "authType": ["simple"], "bindDn": [ldap["bindDn"]], "bindCredential": [ldap["adminPassword"]],
                "searchScope": ["2"], "useTruststoreSpi": ["ldapsOnly"], "connectionPooling": ["true"],
                "pagination": ["true"], "batchSizeForSync": ["1000"], "fullSyncPeriod": ["-1"],
                "changedSyncPeriod": ["-1"], "cachePolicy": ["DEFAULT"], "allowKerberosAuthentication": ["false"],
                "uemDomainCode": [code], "uemDomainLabel": [domain["label"]], "uemDomainDnsName": [domain["dnsName"]],
                "uemClientId": [domain["clientId"]],
            },
        }
        write_json(FEDERATION_DIR / f"domain-{code}.json", federation)


def generate_compose(config: dict) -> dict:
    canonical = config["canonicalDomain"]
    realm = config["realm"]
    proxy = realm["domainAAuthProxy"]
    metadata = canonical["storage"]["metadataDatabase"]
    objects = canonical["storage"]["objectStorage"]
    services, volumes = {}, {"keycloak-db": {}, metadata["service"]: {}, objects["dataVolume"]: {}}
    directories = config["directoryDomains"]
    service_network = "service-inout"
    unsecure_network = "unsecure-domain-a"
    data_network = "uem-data"
    vdi_networks = {domain["code"]: f"vdi-domain-{domain['code']}" for domain in directories}
    networks = {service_network: {}, unsecure_network: {}, data_network: {}, **{name: {} for name in vdi_networks.values()}}
    for domain in directories:
        ldap = domain["ldap"]
        service = ldap["service"]
        data_volume, config_volume = service, f"{service}-config"
        volumes[data_volume], volumes[config_volume] = {}, {}
        services[service] = {
            "build": {"context": "./ldap", "args": {"LDAP_USERS_LDIF": ldap["usersLdif"]}},
            "environment": {"LDAP_ORGANISATION": ldap["organisation"], "LDAP_DOMAIN": domain["dnsName"], "LDAP_ADMIN_PASSWORD": ldap["adminPassword"], "LDAP_TLS": "false"},
            "volumes": [f"{data_volume}:/var/lib/ldap", f"{config_volume}:/etc/ldap/slapd.d"],
            "networks": [service_network],
            "healthcheck": {"test": ["CMD-SHELL", f"ldapsearch -x -H ldap://localhost:389 -D '{ldap['bindDn']}' -w \"$$LDAP_ADMIN_PASSWORD\" -b '{domain['dnsName'].replace('.', ',dc=').join(['dc=', ''])}' -s base dn >/dev/null"], "interval": "5s", "timeout": "5s", "retries": 30},
        }
    services["postgres"] = {"image": "postgres:16-alpine", "environment": {"POSTGRES_DB": "keycloak", "POSTGRES_USER": "keycloak", "POSTGRES_PASSWORD": "keycloak-poc-only"}, "volumes": ["keycloak-db:/var/lib/postgresql/data"], "networks": [service_network], "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U keycloak"], "interval": "5s", "timeout": "3s", "retries": 20}}
    services[metadata["service"]] = {
        "image": metadata["image"],
        "environment": {"POSTGRES_DB": metadata["database"], "POSTGRES_USER": metadata["user"], "POSTGRES_PASSWORD": metadata["password"]},
        "volumes": [f"{metadata['service']}:/var/lib/postgresql/data"],
        "networks": [data_network],
        "healthcheck": {"test": ["CMD-SHELL", f"pg_isready -U {metadata['user']} -d {metadata['database']}"], "interval": "5s", "timeout": "3s", "retries": 20},
    }
    services[objects["service"]] = {
        "image": objects["image"],
        "command": ["/garage", "server", "--single-node", "--default-bucket"],
        "environment": {
            "GARAGE_CONFIG_FILE": "/etc/garage.toml", "GARAGE_DEFAULT_ACCESS_KEY": objects["accessKey"],
            "GARAGE_DEFAULT_SECRET_KEY": objects["secretKey"], "GARAGE_DEFAULT_BUCKET": objects["bucket"],
        },
        "ports": [f"{objects['apiPort']}:3900", f"{objects['adminPort']}:3903"],
        "volumes": ["./garage/garage.toml:/etc/garage.toml:ro", f"{objects['dataVolume']}:/var/lib/garage"],
        "networks": [data_network],
        "healthcheck": {"test": ["CMD", "/garage", "status"], "interval": "5s", "timeout": "5s", "retries": 30},
    }
    depends = {"postgres": {"condition": "service_healthy"}, **{d["ldap"]["service"]: {"condition": "service_healthy"} for d in directories}}
    direct_keycloak_url = f"http://{realm['keycloakHost']}:{realm['keycloakPort']}"
    domain_a_keycloak_url = f"http://{proxy['publicHost']}:{proxy['port']}{proxy['path']}"
    services["keycloak"] = {
        "build": {"context": "./keycloak", "args": {"KEYCLOAK_VERSION": "26.3.3"}},
        "command": ["start-dev", "--import-realm"],
        "environment": {
            "KC_DB": "postgres", "KC_DB_URL": "jdbc:postgresql://postgres:5432/keycloak",
            "KC_DB_USERNAME": "keycloak", "KC_DB_PASSWORD": "keycloak-poc-only",
            "KC_BOOTSTRAP_ADMIN_USERNAME": "admin", "KC_BOOTSTRAP_ADMIN_PASSWORD": "${KEYCLOAK_ADMIN_PASSWORD:-admin-poc-only}",
            "KC_HOSTNAME_STRICT": "false", "KC_HTTP_ENABLED": "true", "KC_PROXY_HEADERS": "xforwarded",
            "KC_PROXY_TRUSTED_ADDRESSES": "172.16.0.0/12",
        },
        "ports": [f"{realm['keycloakPort']}:8080"],
        "networks": [service_network, *vdi_networks.values()],
        "volumes": ["./keycloak/realm:/opt/keycloak/data/import:ro"], "depends_on": depends,
    }
    services[proxy["service"]] = {
        "image": proxy["image"], "ports": [f"{proxy['port']}:8080"],
        "volumes": ["./keycloak/domain-a-proxy/generated-nginx.conf:/etc/nginx/nginx.conf:ro"],
        "networks": [unsecure_network, service_network],
        "depends_on": {"keycloak": {"condition": "service_started"}},
        "healthcheck": {"test": ["CMD-SHELL", f"wget -q -O /dev/null http://127.0.0.1:8080{proxy['path']}/realms/{config['realm']['name']}/.well-known/openid-configuration"], "interval": "5s", "timeout": "3s", "retries": 30},
    }
    services["keycloak-config"] = {"image": "curlimages/curl:8.14.1", "environment": {"KEYCLOAK_ADMIN_PASSWORD": "${KEYCLOAK_ADMIN_PASSWORD:-admin-poc-only}", "KEYCLOAK_REALM": config["realm"]["name"]}, "volumes": ["./keycloak/configure:/config:ro"], "networks": [service_network], "entrypoint": ["/bin/sh", "/config/configure-user-profile.sh"], "depends_on": ["keycloak"]}

    client_env = {f"UEM_CLIENT_SECRET_{d['code'].upper().replace('-', '_')}": d["clientSecret"] for d in [config["canonicalDomain"], *directories]}
    client_env["UEM_LINK_CLIENT_SECRET"] = config["linkClient"]["clientSecret"]
    storage_env = {
        "UEM_DATABASE_URL": f"postgresql://{quote(metadata['user'], safe='')}:{quote(metadata['password'], safe='')}@{metadata['service']}:5432/{quote(metadata['database'], safe='')}",
        "UEM_S3_ENDPOINT": f"http://{objects['service']}:3900", "UEM_S3_BUCKET": objects["bucket"],
        "UEM_S3_ACCESS_KEY": objects["accessKey"], "UEM_S3_SECRET_KEY": objects["secretKey"], "UEM_S3_REGION": objects["region"],
    }
    common_env = {"KEYCLOAK_REALM": config["realm"]["name"], "UEM_SESSION_SECRET": "${UEM_SESSION_SECRET:-local-poc-change-me}", "UEM_DOMAIN_CONFIG": "/config/domains.json", **storage_env, **client_env}
    for domain in [config["canonicalDomain"], *directories]:
        is_canonical = domain is config["canonicalDomain"]
        environment = {
            **common_env,
            "KEYCLOAK_INTERNAL_URL": f"http://{proxy['service']}:8080{proxy['path']}" if is_canonical else "http://keycloak:8080",
            "KEYCLOAK_PUBLIC_URL": domain_a_keycloak_url if is_canonical else direct_keycloak_url,
            "KEYCLOAK_ISSUER": f"http://{proxy['publicHost']}:{proxy['port']}/realms/{realm['name']}" if is_canonical else f"{direct_keycloak_url}/realms/{realm['name']}",
            "KEYCLOAK_BACKCHANNEL_HOST": f"{proxy['publicHost']}:{proxy['port']}" if is_canonical else f"{realm['keycloakHost']}:{realm['keycloakPort']}",
            "UEM_PUBLIC_URL": f"http://localhost:{domain['port']}",
            "UEM_ALLOWED_ZONES": f"{domain['code']},link" if is_canonical else domain["code"],
            "UEM_SESSION_COOKIE_NAME": f"uem_domain_{domain['code']}_session",
        }
        app_networks = [unsecure_network, data_network] if is_canonical else [vdi_networks[domain["code"]], data_network]
        services[domain["service"]] = {"build": "./uem", "environment": environment, "ports": [f"{domain['port']}:8081"], "volumes": ["./config/domains.json:/config/domains.json:ro"], "networks": app_networks, "depends_on": {"keycloak-config": {"condition": "service_completed_successfully"}, metadata["service"]: {"condition": "service_healthy"}, objects["service"]: {"condition": "service_healthy"}}}
    services["uem-cleanup"] = {"build": "./uem", "command": ["python", "cleanup.py"], "environment": {**storage_env, "UEM_CLEANUP_TIMEZONE": "Europe/Zurich"}, "networks": [data_network], "depends_on": {canonical["service"]: {"condition": "service_started"}, metadata["service"]: {"condition": "service_healthy"}, objects["service"]: {"condition": "service_healthy"}}}
    return {"x-generated": "Run python scripts/generate-domain-config.py after editing config/domains.json", "services": services, "volumes": volumes, "networks": networks}


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def generate_garage_config(config: dict) -> str:
    objects = config["canonicalDomain"]["storage"]["objectStorage"]
    return f'''# Generated from config/domains.json. Do not edit directly.
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "[::]:3901"
rpc_public_addr = "{objects['service']}:3901"
rpc_secret = "{objects['rpcSecret']}"

[s3_api]
s3_region = "{objects['region']}"
api_bind_addr = "[::]:3900"
root_domain = ".s3.garage.localhost"

[admin]
api_bind_addr = "[::]:3903"
admin_token = "{objects['adminToken']}"
metrics_require_token = false
'''


def generate_domain_a_proxy_config(config: dict) -> str:
    realm = config["realm"]
    proxy = realm["domainAAuthProxy"]
    prefix = proxy["path"]
    public_origin = f"http://{proxy['publicHost']}:{proxy['port']}"
    realm_path = f"/realms/{realm['name']}/"
    prefixed_realm_path = f"{prefix}{realm_path}"
    prefixed_resource_path = f"{prefix}/resources/"
    return f'''# Generated from config/domains.json. Do not edit directly.
events {{}}

http {{
    server_tokens off;

    server {{
        listen 8080;

        # Only the configured UEM realm and its static login resources are exposed.
        location ^~ {prefixed_realm_path} {{
            rewrite ^{prefix}/(.*)$ /$1 break;
            proxy_pass http://keycloak:8080;
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Host $http_host;
            proxy_set_header X-Forwarded-Prefix {prefix};
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_cookie_path /realms/ {prefix}/realms/;
            proxy_redirect {public_origin}/realms/ {public_origin}{prefix}/realms/;
            sub_filter_once off;
            sub_filter_types text/css application/javascript;
            sub_filter '{public_origin}/realms/' '{public_origin}{prefix}/realms/';
            sub_filter '="/resources/' '="{prefixed_resource_path}';
        }}

        location ^~ {prefixed_resource_path} {{
            rewrite ^{prefix}/(.*)$ /$1 break;
            proxy_pass http://keycloak:8080;
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Host $http_host;
            proxy_set_header X-Forwarded-Prefix {prefix};
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }}

        location / {{ return 404; }}
    }}
}}
'''


def main() -> None:
    config = load_config()
    generate_federations(config)
    write_json(ROOT / "keycloak" / "realm" / "uem-realm.json", generate_realm(config))
    write_json(ROOT / "keycloak" / "configure" / "user-profile.json", generate_user_profile(config))
    write_json(ROOT / "docker-compose.yml", generate_compose(config))
    garage_config = ROOT / "garage" / "garage.toml"
    garage_config.parent.mkdir(parents=True, exist_ok=True)
    garage_config.write_text(generate_garage_config(config), encoding="utf-8")
    DOMAIN_A_PROXY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    DOMAIN_A_PROXY_CONFIG.write_text(generate_domain_a_proxy_config(config), encoding="utf-8")
    print(f"Generated configuration for {len(config['directoryDomains'])} directory domain(s): " + ", ".join(domain["code"] for domain in config["directoryDomains"]))


if __name__ == "__main__":
    main()
