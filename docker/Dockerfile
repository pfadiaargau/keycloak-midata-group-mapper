ARG KEYCLOAK_IMAGE
FROM $KEYCLOAK_IMAGE

USER root
# Ensure directory exists and copy the jar
RUN mkdir -p /opt/keycloak/providers
COPY plugins/*.jar /opt/keycloak/providers/

# KEY FIX: Run the build command to register the provider
RUN /opt/keycloak/bin/kc.sh build

USER 1000

# start-dev is fine for local, it will use the build-time configuration
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev", "--http-enabled=true", "--hostname-strict=false", "--log-level=DEBUG" ]