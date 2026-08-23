#!/bin/sh
set -eu

base=http://keycloak:8080
until curl -fsS "$base/realms/uem/.well-known/openid-configuration" >/dev/null 2>&1; do
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

curl -fsS -X PUT "$base/admin/realms/uem/users/profile" \
  -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' \
  --data-binary @/config/user-profile.json \
  -o /dev/null

realm_id="$(curl -fsS "$base/admin/realms/uem" \
  -H "Authorization: Bearer $token" | sed -n 's/^{"id":"\([^"]*\)","realm".*/\1/p')"
[ -n "$realm_id" ]

create_federation() {
  federation_name="$1"
  federation_file="$2"
  federation="$(curl -fsS -G "$base/admin/realms/uem/components" \
    -H "Authorization: Bearer $token" \
    --data-urlencode "parent=$realm_id" \
    --data-urlencode 'type=org.keycloak.storage.UserStorageProvider' \
    --data-urlencode "name=$federation_name")"

  if ! printf '%s' "$federation" | grep -q "\"name\":\"$federation_name\""; then
    sed "s/@@REALM_ID@@/$realm_id/g" "/config/$federation_file" >"/tmp/$federation_file"
    curl -fsS -X POST "$base/admin/realms/uem/components" \
      -H "Authorization: Bearer $token" \
      -H 'Content-Type: application/json' \
      --data-binary "@/tmp/$federation_file" \
      -o /dev/null
  fi
}

create_federation domain-b-ldap-poc domain-b-federation.json
create_federation domain-c-ldap-poc domain-c-federation.json

echo 'Keycloak user profile and Domain B/C LDAP User Federations configured.'
