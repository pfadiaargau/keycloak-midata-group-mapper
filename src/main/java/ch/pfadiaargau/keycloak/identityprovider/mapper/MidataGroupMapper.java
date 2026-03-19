package ch.pfadiaargau.keycloak.identityprovider.mapper;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class MidataGroupMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "midata-group-mapper";
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(
            Arrays.asList(IdentityProviderSyncMode.values()));
    public static final String[] COMPATIBLE_PROVIDERS = { KeycloakOIDCIdentityProviderFactory.PROVIDER_ID,
            OIDCIdentityProviderFactory.PROVIDER_ID };

    public static final Logger logger = Logger.getLogger(MidataGroupMapper.class.getName());

    // Config Keys
    public static final String CONF_BLACKLIST = "id_blacklist";
    public static final String CONF_GROUP_ROOT_PATH = "group_root_path";

    protected static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        // // Blacklist Field
        // ProviderConfigProperty blacklist = new ProviderConfigProperty();
        // blacklist.setName(CONF_BLACKLIST);
        // blacklist.setLabel("ID Blacklist");
        // blacklist.setHelpText("List with group IDs to exclude from assignment");
        // blacklist.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        // configProperties.add(blacklist);

        // Group Root Field
        ProviderConfigProperty groupRoot = new ProviderConfigProperty();
        groupRoot.setName(CONF_GROUP_ROOT_PATH);
        groupRoot.setLabel("Group Root Path");
        groupRoot.setHelpText(
                "Optional root group path under which to groups from the IdP are located. (Devided by '/' for subgroups, e.g., 'idp/midata')");
        groupRoot.setType(ProviderConfigProperty.STRING_TYPE);
        groupRoot.setRequired(true);
        configProperties.add(groupRoot);
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        logMapperCall("importNewUser", mapperModel, context);
        processMapRules(realm, user, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        logMapperCall("updateBrokeredUser", mapperModel, context);
        processMapRules(realm, user, mapperModel, context);
    }

    private String getGroupPath(GroupModel group) {
        StringBuilder path = new StringBuilder(group.getName());
        GroupModel parent = group.getParent();
        while (parent != null) {
            path.insert(0, parent.getName() + "/");
            parent = parent.getParent();
        }
        logger.info("Midata Group Path " + path.toString());
        return path.toString();
    }

    private void processMapRules(RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

        List<String> blacklist = mapperModel.getConfig().get(CONF_BLACKLIST) != null
                ? Arrays.asList(mapperModel.getConfig().get(CONF_BLACKLIST).split(","))
                : new ArrayList<>();
        String groupRoot = mapperModel.getConfig().get(CONF_GROUP_ROOT_PATH);

        logger.info("Midata-Group-Mapper: Starting group mapping with group root: " + groupRoot + " and blacklist: "
                + blacklist);

        JsonNode jsonNode = (JsonNode) context.getContextData().get(OIDCIdentityProvider.USER_INFO);
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> userInfoMap = objectMapper.convertValue(jsonNode, Map.class);
        String userToken = context.getToken();

        Object roles = userInfoMap.get("roles");
        // Object events = new Object();

        try {
            // Get the idp host url from the context
            String idpHostUrl = null;
            try {
                idpHostUrl = (new URI(
                        (String) context.getIdpConfig().getConfig().get(OIDCIdentityProviderConfig.TOKEN_ENDPOINT_URL)))
                        .getHost();
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }

            // Get user events from idpHostUrl /de/oauth/profile with the user token
            if (idpHostUrl != null && userToken != null) {
                try {
                    String profileUrl = "https://" + idpHostUrl + "/api/people/" + userInfoMap.get("sub");
                    HttpClient httpClient = HttpClient.newHttpClient();
                    HttpRequest request = HttpRequest.newBuilder()
                            .uri(new URI(profileUrl))
                            .header("Authorization", "Bearer " + userToken)
                            .header("X-Scope", "events")
                            .GET()
                            .build();
                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    if (response.statusCode() == 200) {
                        JsonNode profileData = objectMapper.readTree(response.body());
                        logger.info("User profile data: " + profileData.toString());
                    }
                } catch (Exception e) {
                    logger.warning("Failed to retrieve user profile: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            logger.warning("Midata-Group-Mapper: Error processing user events: " + e.getMessage());
        }

        if (!(roles instanceof List)) {
            logger.info("Midata-Group-Mapper: Expected 'roles' to be a List, but got: "
                    + (roles != null ? roles.getClass().getName() : "null"));
            return;
        }

        try {
            // Per role object in the list extract the ID from id field
            List<String> incomingIds = ((List<?>) roles).stream()
                    .filter(role -> role instanceof Map) // Ensure it's a Map
                    .map(role -> (Map<?, ?>) role)
                    .filter(roleMap -> roleMap.containsKey("group_id")) // Ensure it has a 'group_id' field
                    .map(roleMap -> String.valueOf(roleMap.get("group_id"))) // Extract the 'group_id' as String
                    .collect(Collectors.toList());

            // Get all user groups which have an attribute "group_id" and "group_type",
            // "node_kind" = "real" and the top group is the one defined in the config
            List<GroupModel> userMidataGroups = user.getGroupsStream()
                    .filter(g -> g.getFirstAttribute("group_id") != null)
                    .filter(g -> g.getFirstAttribute("group_type") != null)
                    .filter(g -> "real".equals(g.getFirstAttribute("node_kind")))
                    .filter(g -> groupRoot == null || getGroupPath(g).startsWith(groupRoot))
                    .collect(Collectors.toList());

            for (GroupModel group : userMidataGroups) {
                if (!incomingIds.contains(group.getFirstAttribute("group_id"))) {
                    user.leaveGroup(group);
                }
            }

            for (String id : incomingIds) {
                // Check Blacklist first
                if (!blacklist.isEmpty() && blacklist.contains(id)) {
                    continue; // Skip blacklisted IDs
                }

                // assignUserToGroup(realm, user, id, groupRoot);
                assignUserToGroup(realm, user, id, groupRoot);
            }
        } catch (Exception e) {
            logger.warning("Midata-Group-Mapper: Error processing group mappings: " + e.getMessage());
        }
    }

    private void assignUserToGroup(RealmModel realm, UserModel user, String id, String groupRoot) {
        GroupModel group = realm.getGroupsStream()
                .filter(g -> id.equals(g.getFirstAttribute("group_id")))
                .filter(g -> "real".equals(g.getFirstAttribute("node_kind")))
                .filter(g -> groupRoot == null || getGroupPath(g).startsWith(groupRoot))
                .findFirst()
                .orElse(null);
        if (group != null) {
            user.joinGroup(group);
        }
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Midata Group Importer";
    }

    @Override
    public String getDisplayType() {
        return "Midata Group Mapper";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Maps Midata group memberships to Keycloak groups, with optional whitelist/blacklist filtering.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    private void logMapperCall(String phase, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        logger.info("Midata-Group-Mapper [" + phase + "]"
                + " mapperId=" + mapperModel.getId()
                + ", mapperName=" + mapperModel.getName()
                + ", providerId=" + mapperModel.getIdentityProviderMapper()
                + ", idpAlias=" + mapperModel.getIdentityProviderAlias()
                + ", syncMode=" + mapperModel.getSyncMode()
                + ", config=" + mapperModel.getConfig()
                + ", kcIdpAliasFromContext=" + context.getIdpConfig().getAlias());
    }

}
