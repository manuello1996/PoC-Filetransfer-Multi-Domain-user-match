FROM osixia/openldap:1.5.0
ARG LDAP_USERS_LDIF
COPY schema/00-microsoft-compat.schema /container/service/slapd/assets/config/bootstrap/schema/custom/00-microsoft-compat.schema
COPY bootstrap/${LDAP_USERS_LDIF} /container/service/slapd/assets/config/bootstrap/ldif/custom/50-domain-users.ldif
