package ch.pfadiaargau.keycloak.authentication.authenticators.browser;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class MidataSyncAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(MidataSyncAuthenticator.class);
    // private static final String PBSID_GROUP_ATTRIBUTE = "pbs_id";

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        logger.info("MidataSync: authenticate() called.");

        // 1. Check if we have a session and user
        // if (context.getAuthenticationSession() == null || context.getUser() == null) {
        if (context.getAuthenticationSession() == null) {
            logger.debug("MidataSync: No user or session yet. Skipping.");
            context.attempted();
            return;
        }

        logger.info("MidataSync: User " + context.getUser().getUsername() + " is authenticating.");


        SerializedBrokeredIdentityContext serializedBrokeredIdentityContext = new SerializedBrokeredIdentityContext();
        BrokeredIdentityContext idpContext = serializedBrokeredIdentityContext.deserialize(context.getSession(), context.getAuthenticationSession());

        logger.info("MidataSync: IdP Context: " + idpContext);
        logger.info("MidataSync: User Roles: " + idpContext.getAttributes().get("relationships.roles"));
        logger.info("MidataSync: User Roles: " + idpContext.getAttributes().get("data.relationships.roles"));

        // var brokerAlias = idpContext.getIdpConfig().getAlias();
        // logger.info("MidataSync: Broker Alias: " + brokerAlias);

        // // 2. Safely get the token
        // String rawToken =
        // context.getAuthenticationSession().getAuthNote("BROKER_ID_TOKEN");
        // if (rawToken == null) {
        // rawToken =
        // context.getAuthenticationSession().getAuthNote("BROKER_ACCESS_TOKEN");
        // }

        // 3. If no token, just succeed and let the user finish login
        // if (rawToken == null) {
        // logger.debug("MidataSync: No IdP token found in notes.");
        // context.success();
        // return;
        // }

        // // 4. Run your sync logic inside a safe try-catch
        // try {
        // syncMidataGroups(context, rawToken);
        // } catch (Exception e) {
        // logger.error("MidataSync: Failed to process groups", e);
        // // We do NOT call failure() here because we don't want to
        // // lock the user out of Keycloak just because group sync failed.
        // }
        context.success();

    }

    // private void syncMidataGroups(AuthenticationFlowContext context, String
    // rawToken) throws Exception {
    // String[] parts = rawToken.split("\\.");
    // if (parts.length < 2)
    // return;

    // byte[] decodedPayload = java.util.Base64.getDecoder().decode(parts[1]);
    // com.fasterxml.jackson.databind.JsonNode payload =
    // JsonSerialization.readValue(decodedPayload,
    // com.fasterxml.jackson.databind.JsonNode.class);

    // if (payload.has("roles") && payload.get("roles").isArray()) {
    // for (com.fasterxml.jackson.databind.JsonNode roleNode : payload.get("roles"))
    // {
    // String roleId = roleNode.get("id").asText();
    // String roleName = roleNode.get("name").asText();

    // // Perform Group Lookup and Assignment
    // // updateGroupMembership(context, roleId, roleName);
    // }
    // }
    // }

    @Override
    public boolean requiresUser() {
        return true; // This ensures context.getUser() is populated before running
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}