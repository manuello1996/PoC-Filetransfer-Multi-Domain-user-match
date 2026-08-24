#!/bin/sh
set -eu

base=http://keycloak:8080
realm="${KEYCLOAK_REALM:-uem}"
until curl -fsS "$base/realms/$realm/.well-known/openid-configuration" >/dev/null 2>&1; do
  sleep 3
done

token=
until [ -n "$token" ]; do
  token="$(curl -fsS -X POST "$base/realms/master/protocol/openid-connect/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode client_id=admin-cli \
    --data-urlencode username=admin \
    --data-urlencode "password=$KEYCLOAK_ADMIN_PASSWORD" \
    --data-urlencode grant_type=password | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')" || true
  [ -n "$token" ] || sleep 3
done

curl --fail-with-body -sS -X PUT "$base/admin/realms/$realm/users/profile" \
  -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' \
  --data-binary @/config/user-profile.json \
  -o /dev/null

realm_id="$(curl -fsS "$base/admin/realms/$realm" \
  -H "Authorization: Bearer $token" | sed -n 's/^{"id":"\([^"]*\)","realm".*/\1/p')"
[ -n "$realm_id" ]

create_federation() {
  federation_name="$1"
  federation_file="$2"
  federation="$(curl -fsS -G "$base/admin/realms/$realm/components" \
    -H "Authorization: Bearer $token" \
    --data-urlencode "parent=$realm_id" \
    --data-urlencode 'type=org.keycloak.storage.UserStorageProvider' \
    --data-urlencode "name=$federation_name")"
  federation_id="$(printf '%s' "$federation" | sed -n 's/^\[{"id":"\([^"]*\)".*/\1/p')"
  sed "s/@@REALM_ID@@/$realm_id/g" "/config/$federation_file" >"/tmp/federation.json"

  if [ -z "$federation_id" ]; then
    curl --fail-with-body -sS -X POST "$base/admin/realms/$realm/components" \
      -H "Authorization: Bearer $token" \
      -H 'Content-Type: application/json' \
      --data-binary @/tmp/federation.json \
      -o /dev/null
  else
    sed "2i\\  \"id\": \"$federation_id\"," /tmp/federation.json > /tmp/federation-update.json
    curl --fail-with-body -sS -X PUT "$base/admin/realms/$realm/components/$federation_id" \
      -H "Authorization: Bearer $token" \
      -H 'Content-Type: application/json' \
      --data-binary @/tmp/federation-update.json \
      -o /dev/null
  fi
}

for federation_file in /config/generated-federations/*.json; do
  # Do not anchor to end-of-line: generated JSON has CRLF on Windows bind mounts.
  federation_name="$(sed -n 's/^[[:space:]]*"name":[[:space:]]*"\([^"]*\)".*/\1/p' "$federation_file" | sed -n '1p')"
  [ -n "$federation_name" ]
  create_federation "$federation_name" "generated-federations/$(basename "$federation_file")"
done

echo "Keycloak user profile and generated LDAP User Federations configured for realm $realm."
