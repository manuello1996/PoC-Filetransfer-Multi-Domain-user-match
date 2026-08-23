ARG KEYCLOAK_VERSION=26.3.3

FROM maven:3.9-eclipse-temurin-21 AS provider-build
ARG KEYCLOAK_VERSION
WORKDIR /build
COPY provider/pom.xml .
COPY provider/src ./src
RUN mvn -q -DskipTests -Dkeycloak.version=${KEYCLOAK_VERSION} package

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}
COPY --from=provider-build /build/target/uem-poc-authenticator.jar /opt/keycloak/providers/uem-poc-authenticator.jar
COPY theme/uem-poc /opt/keycloak/themes/uem-poc
RUN /opt/keycloak/bin/kc.sh build
