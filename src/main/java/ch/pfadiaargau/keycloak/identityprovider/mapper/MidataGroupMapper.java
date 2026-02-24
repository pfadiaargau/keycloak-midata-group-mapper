package ch.pfadiaargau.keycloak.identityprovider.mapper;

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
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));
    public static final String[] COMPATIBLE_PROVIDERS = {KeycloakOIDCIdentityProviderFactory.PROVIDER_ID, OIDCIdentityProviderFactory.PROVIDER_ID};


    public static final Logger logger = Logger.getLogger(MidataGroupMapper.class.getName());

    // Config Keys
    // public static final String CONF_WHITELIST = "id_whitelist";
    // public static final String CONF_BLACKLIST = "id_blacklist";
    public static final String CONF_GROUP_ROOT_PATH = "group_root_path";

    protected static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
    //     // Whitelist Field
    //     ProviderConfigProperty whitelist = new ProviderConfigProperty();
    //     whitelist.setName(CONF_WHITELIST);
    //     whitelist.setLabel("ID Whitelist");
    //     whitelist.setHelpText("Comma-separated list of IDs allowed to be created as roles.");
    //     whitelist.setType(ProviderConfigProperty.STRING_TYPE);
    //     configProperties.add(whitelist);

    //     // Blacklist Field
    //     ProviderConfigProperty blacklist = new ProviderConfigProperty();
    //     blacklist.setName(CONF_BLACKLIST);
    //     blacklist.setLabel("ID Blacklist");
    //     blacklist.setHelpText("Comma-separated list of IDs that MUST NOT be created as roles.");
    //     blacklist.setType(ProviderConfigProperty.STRING_TYPE);
    //     configProperties.add(blacklist);
    
        // Group Root Field
        ProviderConfigProperty groupRoot = new ProviderConfigProperty();
        groupRoot.setName(CONF_GROUP_ROOT_PATH);
        groupRoot.setLabel("Group Root Path");
        groupRoot.setHelpText("Optional root group path under which to groups from the IdP are located. (Devided by '/' for subgroups, e.g., 'idp/midata')");
        groupRoot.setType(ProviderConfigProperty.STRING_TYPE);
        groupRoot.setRequired(true);
        configProperties.add(groupRoot);
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, 
                              IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        processMapRules(realm, user, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, 
                                   IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        processMapRules(realm, user, mapperModel, context);
    }

    private String getGroupPath(GroupModel group) {
        StringBuilder path = new StringBuilder(group.getName());
        GroupModel parent = group.getParent();
        while (parent != null) {
            path.insert(0, parent.getName() + "/");
            parent = parent.getParent();
        }
        return path.toString();
    }

    private void processMapRules(RealmModel realm, UserModel user, 
                                 IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        
        // List<String> whitelist = parseConfig(mapperModel.getConfig().get(CONF_WHITELIST));
        // List<String> blacklist = parseConfig(mapperModel.getConfig().get(CONF_BLACKLIST));
        // String groupRoot = mapperModel.getConfig().get(CONF_GROUP_ROOT_PATH);

        JsonNode jsonNode = (JsonNode) context.getContextData().get(OIDCIdentityProvider.USER_INFO);
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> userInfoMap = objectMapper.convertValue(jsonNode, Map.class);
        Object roles = userInfoMap.get("roles");

        
        if (!(roles instanceof List)) {
            logger.info("Expected 'roles' to be a List, but got: " + (roles != null ? roles.getClass().getName() : "null"));
            return;
        }
        
        // Per role object in the list extract the ID from id field
        List<String> incomingIds = ((List<?>) roles).stream()
            .filter(role -> role instanceof Map) // Ensure it's a Map
            .map(role -> (Map<?, ?>) role)
            .filter(roleMap -> roleMap.containsKey("group_id")) // Ensure it has a 'group_id' field
            .map(roleMap -> String.valueOf(roleMap.get("group_id"))) // Extract the 'group_id' as String
            .collect(Collectors.toList());

         // Get all user groups which have an attribute "group_id" and "group_type", "node_kind" = "real" and the top group is the one defined in the config
        List<GroupModel> userMidataGroups = user.getGroupsStream()
            .filter(g -> g.getFirstAttribute("group_id") != null)
            .filter(g -> g.getFirstAttribute("group_type") != null)
            .filter(g -> "real".equals(g.getFirstAttribute("node_kind")))
            // .filter(g -> getGroupPath(g).startsWith(groupRoot))
            .collect(Collectors.toList());

        for (GroupModel group : userMidataGroups) {
            if (!incomingIds.contains(group.getFirstAttribute("group_id"))) {
                user.leaveGroup(group);
            }
        }

        for (String id : incomingIds) {
            // Check Blacklist first
            // if (!blacklist.isEmpty() && blacklist.contains(id)) {
            //     continue; // Skip blacklisted IDs
            // }

            // // Check Whitelist (if whitelist is set, ID must be in it)
            // if (!whitelist.isEmpty() && !whitelist.contains(id)) {
            //     continue; // Skip if not in whitelist
            // }

            // assignUserToGroup(realm, user, id, groupRoot);
            assignUserToGroup(realm, user, id, null);
        }
    }

    private void assignUserToGroup(RealmModel realm, UserModel user, String id, String groupRoot) {
        GroupModel group = realm.getGroupsStream()
            .filter(g -> id.equals(g.getFirstAttribute("group_id")))
            .filter(g -> "real".equals(g.getFirstAttribute("node_kind")))
            // .filter(g -> getGroupPath(g).startsWith(groupRoot))
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

    
}
