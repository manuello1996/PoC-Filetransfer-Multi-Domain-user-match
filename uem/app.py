import hashlib
import html
import json
import os
import secrets
import uuid
from functools import wraps
from pathlib import Path
from urllib.parse import quote, urlencode

import boto3
import jwt
import psycopg
import requests
from botocore.config import Config
from flask import Flask, Response, abort, redirect, request, session, stream_with_context, url_for
from psycopg.rows import dict_row

app = Flask(__name__)
app.secret_key = os.environ.get("UEM_SESSION_SECRET", "local-poc-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME=os.environ.get("UEM_SESSION_COOKIE_NAME", "uem_session"),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
)

INTERNAL_KC = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
PUBLIC_KC = os.environ.get("KEYCLOAK_PUBLIC_URL", "http://localhost:8080")
REALM = os.environ.get("KEYCLOAK_REALM", "uem")
KC_ISSUER = os.environ.get("KEYCLOAK_ISSUER", f"{PUBLIC_KC}/realms/{REALM}")
KEYCLOAK_BACKCHANNEL_HOST = os.environ.get("KEYCLOAK_BACKCHANNEL_HOST")
KEYCLOAK_HEADERS = {"Host": KEYCLOAK_BACKCHANNEL_HOST} if KEYCLOAK_BACKCHANNEL_HOST else {}
PUBLIC_APP = os.environ.get("UEM_PUBLIC_URL", "http://localhost:8081")
DOMAIN_CONFIG_PATH = Path(os.environ.get("UEM_DOMAIN_CONFIG", Path(__file__).resolve().parents[1] / "config" / "domains.json"))
DOMAIN_CONFIG = json.loads(DOMAIN_CONFIG_PATH.read_text(encoding="utf-8"))
CANONICAL_DOMAIN = DOMAIN_CONFIG["canonicalDomain"]
DIRECTORY_DOMAINS = {domain["code"]: domain for domain in DOMAIN_CONFIG["directoryDomains"]}
ALLOWED_ZONES = {zone.strip() for zone in os.environ.get("UEM_ALLOWED_ZONES", f"{CANONICAL_DOMAIN['code']},link").split(",") if zone.strip()}
METADATA_CONFIG = CANONICAL_DOMAIN["storage"]["metadataDatabase"]
OBJECT_CONFIG = CANONICAL_DOMAIN["storage"]["objectStorage"]
DEFAULT_DATABASE_URL = f"postgresql://{quote(METADATA_CONFIG['user'], safe='')}:{quote(METADATA_CONFIG['password'], safe='')}@{METADATA_CONFIG['service']}:5432/{quote(METADATA_CONFIG['database'], safe='')}"
DATABASE_URL = os.environ.get("UEM_DATABASE_URL", DEFAULT_DATABASE_URL)
S3_ENDPOINT = os.environ.get("UEM_S3_ENDPOINT", f"http://{OBJECT_CONFIG['service']}:3900")
S3_BUCKET = os.environ.get("UEM_S3_BUCKET", OBJECT_CONFIG["bucket"])
S3_REGION = os.environ.get("UEM_S3_REGION", OBJECT_CONFIG["region"])
S3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=os.environ.get("UEM_S3_ACCESS_KEY", OBJECT_CONFIG["accessKey"]),
    aws_secret_access_key=os.environ.get("UEM_S3_SECRET_KEY", OBJECT_CONFIG["secretKey"]),
    region_name=S3_REGION,
    config=Config(s3={"addressing_style": "path"}),
)
ALL_LOGIN_DOMAINS = {CANONICAL_DOMAIN["code"]: CANONICAL_DOMAIN, **DIRECTORY_DOMAINS}
CLIENTS = {
    code: (domain["clientId"], os.environ.get(f"UEM_CLIENT_SECRET_{code.upper().replace('-', '_')}", domain["clientSecret"]))
    for code, domain in ALL_LOGIN_DOMAINS.items()
}
CLIENTS.update({
    "link": (DOMAIN_CONFIG["linkClient"]["clientId"], os.environ.get("UEM_LINK_CLIENT_SECRET", DOMAIN_CONFIG["linkClient"]["clientSecret"])),
    "unlink": (DOMAIN_CONFIG["linkClient"]["clientId"], os.environ.get("UEM_LINK_CLIENT_SECRET", DOMAIN_CONFIG["linkClient"]["clientSecret"])),
})
ACTION_ZONES = {
    "link": "uem-link-directory",
    "unlink": "uem-unlink-directory",
}

def db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def initialize_storage():
    S3.head_bucket(Bucket=S3_BUCKET)

    with db() as connection:
        # Every UEM instance and Gunicorn worker starts concurrently. PostgreSQL's
        # CREATE TABLE IF NOT EXISTS can still race in the system catalogs, so keep
        # the small bootstrap migration serialized across all processes.
        connection.execute("SELECT pg_advisory_xact_lock(894360574)")
        connection.execute("""CREATE TABLE IF NOT EXISTS app_state (
            key TEXT PRIMARY KEY, value TEXT NOT NULL
        )""")
        connection.execute("""CREATE TABLE IF NOT EXISTS files (
            file_id UUID PRIMARY KEY, owner_sub TEXT NOT NULL, object_key TEXT NOT NULL UNIQUE,
            original_filename TEXT NOT NULL, size BIGINT NOT NULL, sha256 TEXT NOT NULL,
            source_zone TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        connection.execute("""CREATE TABLE IF NOT EXISTS oidc_sessions (
            session_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, refresh_token TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")


initialize_storage()


def application_instance_id():
    candidate = str(uuid.uuid4())
    with db() as connection:
        connection.execute("INSERT INTO app_state(key, value) VALUES('instance_id', %s) ON CONFLICT (key) DO NOTHING", (candidate,))
        return connection.execute("SELECT value FROM app_state WHERE key='instance_id'").fetchone()["value"]


APP_INSTANCE_ID = application_instance_id()


def page(title, body):
    active_code = next((code for code in ALL_LOGIN_DOMAINS if code in ALLOWED_ZONES), CANONICAL_DOMAIN["code"])
    active_domain = ALL_LOGIN_DOMAINS[active_code]
    zone_label = f"{active_domain['label'].upper()} / {'WORKSTATION' if active_code == CANONICAL_DOMAIN['code'] else 'VDI'}"
    heartbeat = """
    <script>
    setInterval(async () => {
      try {
        const response = await fetch('/session/status', {credentials: 'same-origin', cache: 'no-store'});
        if (response.status === 401) window.location.replace('/');
      } catch (_) {
        // A temporary network failure does not reload or destroy the current page.
      }
    }, 30000);
    </script>""" if session.get("sub") else ""
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
    <meta name=viewport content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title>
    <link rel=stylesheet href=/static/uem.css></head><body>
    <div class=app-shell><header class=topbar><a class=brand href=/>UEM//TRANSFER</a>
    <span class=environment>{zone_label}</span></header>
    <main class=workspace>{body}</main>{heartbeat}</div></body></html>"""


def zone_allowed(zone):
    return zone in ALLOWED_ZONES or (zone in ACTION_ZONES and "link" in ALLOWED_ZONES)


def linked_accounts():
    return {
        domain: session.get(f"domain_{domain}_identity")
        for domain in DIRECTORY_DOMAINS
        if session.get(f"domain_{domain}_identity")
    }


def has_active_link():
    return bool(linked_accounts()) and session.get("link_status") == "ACTIVE"


def client_secret_for(client_id):
    return next((secret for configured_id, secret in CLIENTS.values() if configured_id == client_id), None)


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "sub" not in session or session.get("app_instance_id") != APP_INSTANCE_ID:
            session.clear()
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapped


@app.get("/")
def index():
    if "sub" in session:
        if session.get("app_instance_id") == APP_INSTANCE_ID:
            return redirect(url_for("files"))
        session.clear()
    for domain, definition in DIRECTORY_DOMAINS.items():
        if domain in ALLOWED_ZONES:
            label = html.escape(definition["label"])
            return page(f"{definition['label']} VDI — UEM PoC", f"""
              <section class=welcome><div class=eyebrow>SECURE ENTRY POINT</div><h1>{label} VDI</h1>
              <p class=lead>This endpoint represents the separate {label} virtual desktop.</p>
              <div class=entry-card><div><h2>Continue with {label}</h2><p>Use a {label} LDAP identity already linked to your canonical account.</p></div>
              <a class="btn btn-primary" href=/login/{domain}>Enter from {label}</a></div></section>""")
    code = CANONICAL_DOMAIN["code"]
    label = html.escape(CANONICAL_DOMAIN["label"])
    return page(f"{CANONICAL_DOMAIN['label']} workstation — UEM PoC", f"""
      <section class=welcome><div class=eyebrow>SECURE ENTRY POINT</div><h1>{label} workstation</h1>
      <p class=lead>This endpoint represents the {label} workstation.</p>
      <div class=entry-card><div><h2>Continue with {label}</h2><p>Enter a simulated Windows username. Keycloak requires at least one linked directory account before UEM opens.</p></div>
      <a class="btn btn-primary" href=/login/{code}>Enter from {label}</a></div></section>""")


@app.get("/login/<zone>")
def login(zone):
    if zone not in CLIENTS or not zone_allowed(zone):
        abort(404)
    client_id, _ = CLIENTS[zone]
    state = secrets.token_urlsafe(24)
    if zone in ACTION_ZONES:
        if "sub" not in session or session.get("app_instance_id") != APP_INSTANCE_ID:
            session.clear()
            return redirect(url_for("index"))
        session["return_zone"] = session.get("zone", CANONICAL_DOMAIN["code"])
        session["expected_sub"] = session["sub"]
        session["return_oidc_client_id"] = session.get("oidc_client_id")
        session["return_oidc_session_id"] = session.get("oidc_session_id")
    else:
        session.clear()
    session["oauth_state"] = state
    session["oauth_zone"] = zone
    parameters = {
        "client_id": client_id, "response_type": "code", "scope": "openid profile",
        "redirect_uri": f"{PUBLIC_APP}/callback/{zone}", "state": state,
    }
    if zone in ACTION_ZONES:
        parameters["kc_action"] = ACTION_ZONES[zone]
    query = urlencode(parameters)
    return redirect(f"{PUBLIC_KC}/realms/{REALM}/protocol/openid-connect/auth?{query}")


@app.get("/callback/<zone>")
def callback(zone):
    if zone not in CLIENTS or not zone_allowed(zone) or zone != session.get("oauth_zone") or request.args.get("state") != session.get("oauth_state"):
        abort(400, "Invalid OAuth state")
    client_id, client_secret = CLIENTS[zone]
    response = requests.post(
        f"{INTERNAL_KC}/realms/{REALM}/protocol/openid-connect/token",
        headers=KEYCLOAK_HEADERS,
        data={"grant_type": "authorization_code", "code": request.args.get("code"),
              "redirect_uri": f"{PUBLIC_APP}/callback/{zone}", "client_id": client_id,
              "client_secret": client_secret}, timeout=10)
    response.raise_for_status()
    token_response = response.json()
    token = token_response["id_token"]
    key = jwt.PyJWKClient(f"{INTERNAL_KC}/realms/{REALM}/protocol/openid-connect/certs").get_signing_key_from_jwt(token)
    claims = jwt.decode(token, key.key, algorithms=["RS256"], audience=client_id,
                        issuer=KC_ISSUER)
    if zone in ACTION_ZONES and claims["sub"] != session.get("expected_sub"):
        abort(403, "The link-management action returned a different canonical identity.")
    resulting_zone = session.get("return_zone", CANONICAL_DOMAIN["code"]) if zone in ACTION_ZONES else zone
    if zone in ACTION_ZONES:
        requests.post(
            f"{INTERNAL_KC}/realms/{REALM}/protocol/openid-connect/revoke",
            headers=KEYCLOAK_HEADERS,
            auth=(client_id, client_secret),
            data={"token": token_response["refresh_token"], "token_type_hint": "refresh_token"},
            timeout=10,
        ).raise_for_status()
        oidc_client_id = session.get("return_oidc_client_id")
        oidc_session_id = session.get("return_oidc_session_id")
    else:
        oidc_client_id = client_id
        oidc_session_id = secrets.token_urlsafe(32)
        with db() as connection:
            connection.execute(
                "INSERT INTO oidc_sessions(session_id, client_id, refresh_token) VALUES(%s,%s,%s)",
                (oidc_session_id, client_id, token_response["refresh_token"]),
            )
    identity_claims = {f"domain_{domain}_identity": claims.get(f"domain_{domain}_identity") for domain in DIRECTORY_DOMAINS}
    session.clear()
    session.update(
        sub=claims["sub"],
        username=claims.get("preferred_username", "canonical-user"),
        zone=resulting_zone,
        link_status=claims.get("link_status"),
        app_instance_id=APP_INSTANCE_ID,
        csrf_token=secrets.token_urlsafe(32),
        oidc_client_id=oidc_client_id,
        oidc_session_id=oidc_session_id,
        **identity_claims,
    )
    return redirect(url_for("settings" if zone in ACTION_ZONES else "files"))


@app.get("/link-account")
@login_required
def link_account():
    if "link" not in ALLOWED_ZONES:
        abort(404)
    return redirect(url_for("login", zone="link"))


@app.get("/settings")
@login_required
def settings():
    if "link" not in ALLOWED_ZONES:
        abort(404)
    accounts = linked_accounts()
    cards = []
    for domain, definition in DIRECTORY_DOMAINS.items():
        account = accounts.get(domain)
        label = html.escape(definition["label"])
        if account:
            remove = ("<a class='btn btn-danger btn-sm' href='/login/unlink'>Remove link</a>"
                      if len(accounts) > 1 else
                      "<span class=muted>Required while it is the only link</span>")
            cards.append(f"<div class=link-card><div><span class=meta-label>{label.upper()}</span>"
                         f"<strong>{html.escape(account)}</strong><span class=badge badge-active>ACTIVE</span></div>{remove}</div>")
        else:
            cards.append(f"<div class='link-card link-card-empty'><div><span class=meta-label>{label.upper()}</span>"
                         "<strong>Not linked</strong></div></div>")
    body = f"""<section class=page-heading><div><div class=eyebrow>ACCOUNT SETTINGS</div><h1>Linked directory accounts</h1>
      <p class=lead>Add accounts for other VDI domains or remove a link after another active link exists.</p></div>
      <a class='btn btn-secondary' href=/files>Back to files</a></section>
      <section class=settings-grid>{''.join(cards)}</section>
      <section class=settings-actions><a class='btn btn-primary' href=/login/link>Add directory account</a></section>"""
    return page("Account settings", body)


@app.route("/files", methods=["GET", "POST"])
@login_required
def files():
    if request.method == "POST":
        if not has_active_link():
            abort(403, "At least one verified active directory linkage is required before uploading files.")
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            abort(400, "Choose a file")
        file_id = str(uuid.uuid4())
        object_key = f"{session['sub']}/{file_id}"
        digest = hashlib.sha256()
        size = 0
        while chunk := upload.stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        upload.stream.seek(0)
        S3.upload_fileobj(
            upload.stream, S3_BUCKET, object_key,
            ExtraArgs={"ContentType": upload.mimetype or "application/octet-stream"},
        )
        try:
            with db() as connection:
                connection.execute(
                    "INSERT INTO files(file_id,owner_sub,object_key,original_filename,size,sha256,source_zone) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                    (file_id, session["sub"], object_key, upload.filename, size, digest.hexdigest(), session["zone"].upper()),
                )
        except Exception:
            S3.delete_object(Bucket=S3_BUCKET, Key=object_key)
            raise
        return redirect(url_for("files"))

    if not has_active_link():
        if "link" in ALLOWED_ZONES:
            return redirect(url_for("link_account"))
        abort(403, "At least one verified active directory linkage is required.")

    with db() as connection:
        rows = connection.execute("SELECT * FROM files WHERE owner_sub=%s ORDER BY created_at DESC", (session["sub"],)).fetchall()
    csrf_token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
    table = "".join(
        f"<tr><td><span class=file-name>{html.escape(r['original_filename'])}</span></td>"
        f"<td class=mono>{r['size']:,}</td><td><code>{r['sha256'][:12]}…</code></td>"
        f"<td><span class=badge>{html.escape(r['source_zone'])}</span></td>"
        f"<td class=mono>{html.escape(str(r['created_at']))}</td><td><div class=row-actions>"
        f"<a class='btn btn-secondary btn-sm' href='/files/{r['file_id']}'>Download</a>"
        f"<form method=post action='/files/{r['file_id']}/delete' onsubmit=\"return confirm('Delete this file permanently?')\">"
        f"<input type=hidden name=csrf_token value='{html.escape(csrf_token)}'>"
        f"<button class='btn btn-danger btn-sm' type=submit>Delete</button></form></div></td></tr>"
        for r in rows
    )
    account_summary = ", ".join(f"{domain.upper()}:{account}" for domain, account in linked_accounts().items())
    upload_form = ("<form class=upload-form method=post enctype=multipart/form-data>"
                   "<label class=file-picker><span>Choose a file</span><input type=file name=file required></label>"
                   "<button class='btn btn-primary' type=submit>Upload file</button></form>")
    settings_button = "<a class='btn btn-secondary' href=/settings>Settings</a>" if "link" in ALLOWED_ZONES else ""
    body = f"""<section class=page-heading><div><div class=eyebrow>CANONICAL FILE SPACE</div><h1>Your files</h1>
      <p class=lead>Files are available from every linked security zone through the same canonical identity.</p></div>
      <div class=heading-actions>{settings_button}<a class="btn btn-secondary" href=/logout>Log out</a></div></section>
      <section class=identity-strip aria-label="Identity status"><div><span class=meta-label>SIGNED IN VIA</span><strong>{session['zone'].upper()}</strong></div>
      <div><span class=meta-label>DIRECTORY LINKS</span><strong>{html.escape(account_summary or 'none')}</strong></div>
      <div><span class=meta-label>STATUS</span><span class="badge badge-active">{html.escape(session.get('link_status') or 'UNLINKED')}</span></div>
      <div><span class=meta-label>KEYCLOAK SUBJECT</span><code>{html.escape(session['sub'])}</code></div></section>
      <section class=panel><div class=panel-heading><div><h2>Upload</h2><p>Maximum file size: 25 MB</p></div></div>{upload_form}
      <p class=retention-note>Retention policy: files uploaded today are automatically deleted at 23:59 Europe/Zurich.</p></section>
      <section class=panel><div class=panel-heading><div><h2>Stored files</h2><p>{len(rows)} file{'s' if len(rows) != 1 else ''} owned by this identity</p></div></div>
      <div class=table-wrap><table><thead><tr><th>Name</th><th>Bytes</th><th>SHA-256</th><th>Zone</th><th>Uploaded</th><th>Actions</th></tr></thead>
      <tbody>{table or '<tr><td class=empty colspan=6>No files uploaded yet.</td></tr>'}</tbody></table></div></section>"""
    return page("Your files", body)


@app.get("/files/<file_id>")
@login_required
def download(file_id):
    with db() as connection:
        row = connection.execute("SELECT * FROM files WHERE file_id=%s AND owner_sub=%s", (file_id, session["sub"])).fetchone()
    if row is None:
        abort(404)
    stored_object = S3.get_object(Bucket=S3_BUCKET, Key=row["object_key"])
    body = stored_object["Body"]

    def object_chunks():
        try:
            yield from body.iter_chunks(chunk_size=1024 * 1024)
        finally:
            body.close()

    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(row['original_filename'])}",
        "Content-Length": str(stored_object.get("ContentLength", 0)),
    }
    return Response(
        stream_with_context(object_chunks()),
        content_type=stored_object.get("ContentType", "application/octet-stream"),
        headers=headers,
    )


@app.post("/files/<file_id>/delete")
@login_required
def delete_file(file_id):
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("csrf_token", "")
    if not expected_token or not secrets.compare_digest(submitted_token, expected_token):
        abort(400, "Invalid CSRF token")
    with db() as connection:
        row = connection.execute(
            "SELECT object_key FROM files WHERE file_id=%s AND owner_sub=%s",
            (file_id, session["sub"]),
        ).fetchone()
        if row is None:
            abort(404)
        S3.delete_object(Bucket=S3_BUCKET, Key=row["object_key"])
        connection.execute("DELETE FROM files WHERE file_id=%s AND owner_sub=%s", (file_id, session["sub"]))
    return redirect(url_for("files"))


@app.get("/session/status")
def session_status():
    if "sub" not in session or session.get("app_instance_id") != APP_INSTANCE_ID:
        session.clear()
        return {"valid": False}, 401, {"Cache-Control": "no-store"}

    oidc_session_id = session.get("oidc_session_id")
    client_id = session.get("oidc_client_id")
    with db() as connection:
        record = connection.execute(
            "SELECT client_id, refresh_token FROM oidc_sessions WHERE session_id=%s",
            (oidc_session_id,),
        ).fetchone() if oidc_session_id else None

    client_secret = client_secret_for(client_id)
    if record is None or record["client_id"] != client_id or client_secret is None:
        session.clear()
        return {"valid": False}, 401, {"Cache-Control": "no-store"}

    try:
        response = requests.post(
            f"{INTERNAL_KC}/realms/{REALM}/protocol/openid-connect/token/introspect",
            headers=KEYCLOAK_HEADERS,
            auth=(client_id, client_secret),
            data={"token": record["refresh_token"], "token_type_hint": "refresh_token"},
            timeout=5,
        )
        response.raise_for_status()
        active = response.json().get("active") is True
    except (requests.RequestException, ValueError):
        return {"valid": None}, 503, {"Cache-Control": "no-store"}

    if not active:
        with db() as connection:
            connection.execute("DELETE FROM oidc_sessions WHERE session_id=%s", (oidc_session_id,))
        session.clear()
        return {"valid": False}, 401, {"Cache-Control": "no-store"}

    return {"valid": True}, 200, {"Cache-Control": "no-store"}


@app.get("/logout")
def logout():
    client_id = session.get("oidc_client_id")
    oidc_session_id = session.get("oidc_session_id")
    record = None
    if oidc_session_id:
        with db() as connection:
            record = connection.execute(
                "SELECT client_id, refresh_token FROM oidc_sessions WHERE session_id=%s",
                (oidc_session_id,),
            ).fetchone()

    revocation_error = None
    if record is not None and record["client_id"] == client_id:
        client_secret = client_secret_for(client_id)
        try:
            response = requests.post(
                f"{INTERNAL_KC}/realms/{REALM}/protocol/openid-connect/revoke",
                headers=KEYCLOAK_HEADERS,
                auth=(client_id, client_secret),
                data={"token": record["refresh_token"], "token_type_hint": "refresh_token"},
                timeout=10,
            )
            response.raise_for_status()
        except requests.RequestException as error:
            app.logger.exception("Keycloak client-session revocation failed")
            revocation_error = error

    if oidc_session_id:
        with db() as connection:
            connection.execute("DELETE FROM oidc_sessions WHERE session_id=%s", (oidc_session_id,))
    session.clear()
    if revocation_error is not None:
        abort(502, "The local session was closed, but Keycloak client-session revocation failed.")
    return redirect(url_for("index"))


@app.get("/health")
def health():
    return {"status": "ok"}
