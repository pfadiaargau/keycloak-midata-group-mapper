package ch.pfadiaargau.keycloak.identityprovider.mapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
import org.keycloak.representations.AccessTokenResponse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ch.pfadiaargau.model.MidataRole;

public class MidataGroupMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "midata-group-mapper";

    private static final Logger LOGGER = Logger.getLogger(MidataGroupMapper.class.getName());
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private static final Duration MIDATA_REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final int MIDATA_PAGE_SIZE = 100;

    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(
            Arrays.asList(IdentityProviderSyncMode.values()));

    public static final String[] COMPATIBLE_PROVIDERS = {
            KeycloakOIDCIdentityProviderFactory.PROVIDER_ID,
            OIDCIdentityProviderFactory.PROVIDER_ID
    };

    public static final String CONF_BLACKLIST = "id_blacklist";
    public static final String CONF_GROUP_ROOT_PATH = "group_root_path";
    public static final String CONF_ASSIGN_USER_TO_GROUP_NODE = "assign_user_to_group_node";
    public static final String CONF_ASSIGN_USER_TO_ROLES_WITH_NO_ROLE_TYPE = "assign_user_to_roles_with_no_role_type";
    public static final String CONF_MIDATA_API_URL = "midata_api_url";
    public static final String CONF_MIDATA_API_TOKEN = "midata_api_token";

    protected static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty groupRoot = new ProviderConfigProperty();
        groupRoot.setName(CONF_GROUP_ROOT_PATH);
        groupRoot.setLabel("Group Root Path");
        groupRoot.setHelpText(
                "Optional root group path under which groups from the IdP are located. " +
                        "(Separated by '/' for subgroups, e.g. 'idp/midata')");
        groupRoot.setType(ProviderConfigProperty.STRING_TYPE);
        groupRoot.setRequired(true);
        configProperties.add(groupRoot);

        ProviderConfigProperty assignUserToGroupNode = new ProviderConfigProperty();
        assignUserToGroupNode.setName(CONF_ASSIGN_USER_TO_GROUP_NODE);
        assignUserToGroupNode.setLabel("Assign User to Group Node");
        assignUserToGroupNode.setHelpText("Whether to assign users to the exact group with the matching group_id");
        assignUserToGroupNode.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        assignUserToGroupNode.setDefaultValue("true");
        configProperties.add(assignUserToGroupNode);

        ProviderConfigProperty assignUserToRolesWithNoRoleType = new ProviderConfigProperty();
        assignUserToRolesWithNoRoleType.setName(CONF_ASSIGN_USER_TO_ROLES_WITH_NO_ROLE_TYPE);
        assignUserToRolesWithNoRoleType.setLabel("Assign User to Roles with No matching role_type");
        assignUserToRolesWithNoRoleType.setHelpText(
                "Whether to assign users to groups for roles that do not have a matching role_type attribute");
        assignUserToRolesWithNoRoleType.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        assignUserToRolesWithNoRoleType.setDefaultValue("false");
        configProperties.add(assignUserToRolesWithNoRoleType);

        ProviderConfigProperty midataApiUrl = new ProviderConfigProperty();
        midataApiUrl.setName(CONF_MIDATA_API_URL);
        midataApiUrl.setLabel("Midata API URL");
        midataApiUrl.setHelpText("Base URL of the Midata instance used to fetch event participations "
                + "(e.g. 'https://db.scout.ch')");
        midataApiUrl.setType(ProviderConfigProperty.STRING_TYPE);
        midataApiUrl.setDefaultValue("https://db.scout.ch");
        configProperties.add(midataApiUrl);

        ProviderConfigProperty midataApiToken = new ProviderConfigProperty();
        midataApiToken.setName(CONF_MIDATA_API_TOKEN);
        midataApiToken.setLabel("Midata Service Token");
        midataApiToken.setHelpText("Optional Midata service token (sent as X-Token) used to fetch event participations. "
                + "If empty, the user's access token from the identity provider is used, which requires "
                + "the 'api' or 'event_participations' scope.");
        midataApiToken.setType(ProviderConfigProperty.PASSWORD);
        midataApiToken.setSecret(true);
        configProperties.add(midataApiToken);
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

    private void processMapRules(RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

        MapperConfig config = MapperConfig.from(mapperModel);

        LOGGER.info("Midata-Group-Mapper: Starting group mapping with group root: " + config.groupRootPath
                + " and blacklist: " + config.blacklist);

        JsonNode userInfo = getUserInfoNode(context);
        String externalUserId = extractExternalUserId(userInfo);

        List<MidataRole> incomingRoles = extractIncomingRoles(userInfo);
        if (incomingRoles.isEmpty()) {
            LOGGER.info("Midata-Group-Mapper: No incoming roles found");
        }

        Map<String, List<MidataRole>> rolesByGroupId = incomingRoles.stream()
                .filter(role -> !config.blacklist.contains(role.getGroup_id()))
                .collect(Collectors.groupingBy(
                        MidataRole::getGroup_id,
                        LinkedHashMap::new,
                        Collectors.toList()));

        List<GroupModel> existingMappedNodeGroups = getUserMappedNodeGroups(user, config);

        syncExistingMemberships(user, existingMappedNodeGroups, rolesByGroupId, config);
        joinMissingMemberships(realm, user, rolesByGroupId, config);

        syncCollectionMemberships(realm, user, rolesByGroupId, config);

        syncEventMemberships(realm, user, config, externalUserId, getFederatedAccessToken(context));
    }

    private String getFederatedAccessToken(BrokeredIdentityContext context) {
        Object tokenResponse = context.getContextData().get(OIDCIdentityProvider.FEDERATED_ACCESS_TOKEN_RESPONSE);
        if (tokenResponse instanceof AccessTokenResponse accessTokenResponse) {
            return accessTokenResponse.getToken();
        }
        return null;
    }

    private JsonNode getUserInfoNode(BrokeredIdentityContext context) {
        Object userInfo = context.getContextData().get(OIDCIdentityProvider.USER_INFO);
        if (userInfo instanceof JsonNode jsonNode) {
            return jsonNode;
        }

        LOGGER.warning("Midata-Group-Mapper: USER_INFO is missing or not a JsonNode");
        return null;
    }

    private String extractExternalUserId(JsonNode userInfo) {
        if (userInfo == null) {
            return null;
        }

        JsonNode subNode = userInfo.get("sub");
        if (subNode == null || subNode.isNull()) {
            LOGGER.warning("Midata-Group-Mapper: Could not extract external user id from 'sub'");
            return null;
        }

        String externalUserId = subNode.asText(null);
        LOGGER.info("Midata-Group-Mapper: External user id resolved to: " + externalUserId);
        return externalUserId;
    }

    private List<MidataRole> extractIncomingRoles(JsonNode userInfo) {
        if (userInfo == null) {
            return List.of();
        }

        Map<String, Object> userInfoMap = OBJECT_MAPPER.convertValue(userInfo, Map.class);
        Object rolesObject = userInfoMap.get("roles");

        if (!(rolesObject instanceof List<?> rolesList)) {
            LOGGER.info("Midata-Group-Mapper: Expected 'roles' to be a List, but got: "
                    + (rolesObject != null ? rolesObject.getClass().getName() : "null"));
            return List.of();
        }

        return rolesList.stream()
                .filter(Map.class::isInstance)
                .map(Map.class::cast)
                .filter(roleMap -> roleMap.containsKey("group_id") && roleMap.containsKey("role"))
                .map(this::toMidataRole)
                .collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private MidataRole toMidataRole(Map<?, ?> roleMap) {
        return new MidataRole(
                String.valueOf(roleMap.get("group_id")),
                String.valueOf(roleMap.get("group_name")),
                String.valueOf(roleMap.get("role")),
                String.valueOf(roleMap.get("role_class")),
                String.valueOf(roleMap.get("role_name")),
                (List<String>) roleMap.get("permissions"));
    }

    private List<GroupModel> getUserMappedNodeGroups(UserModel user, MapperConfig config) {
        return user.getGroupsStream()
                .filter(isMappedNodeGroup(config))
                .collect(Collectors.toList());
    }

    private Predicate<GroupModel> isMappedNodeGroup(MapperConfig config) {
        return group -> hasAttribute(group, "group_id")
                && hasAttribute(group, "group_type")
                && "real".equals(group.getFirstAttribute("node_kind"))
                && isUnderConfiguredRoot(group, config.groupRootPath);
    }

    private void syncExistingMemberships(UserModel user,
            List<GroupModel> existingMappedNodeGroups,
            Map<String, List<MidataRole>> rolesByGroupId,
            MapperConfig config) {

        for (GroupModel nodeGroup : existingMappedNodeGroups) {
            String groupId = nodeGroup.getFirstAttribute("group_id");
            List<MidataRole> desiredRolesForNode = rolesByGroupId.getOrDefault(groupId, List.of());

            GroupModel rolesCategoryGroup = findRolesCategoryGroup(nodeGroup);
            List<GroupModel> currentRoleGroups = findRoleGroups(rolesCategoryGroup)
                    .collect(Collectors.toList());

            boolean shouldHaveNodeMembership = config.assignUserToGroupNode && !desiredRolesForNode.isEmpty();

            Set<String> desiredRoleValues = desiredRolesForNode.stream()
                    .map(MidataRole::getRole)
                    .collect(Collectors.toSet());

            List<GroupModel> desiredRoleGroups = currentRoleGroups.stream()
                    .filter(group -> desiredRoleValues.contains(group.getFirstAttribute("role_value")))
                    .collect(Collectors.toList());

            boolean shouldHaveRolesCategoryMembership = config.assignUserToRolesWithNoRoleType
                    && !desiredRolesForNode.isEmpty()
                    && desiredRoleGroups.isEmpty()
                    && rolesCategoryGroup != null;

            for (GroupModel currentRoleGroup : currentRoleGroups) {
                boolean shouldKeep = desiredRoleGroups.stream()
                        .anyMatch(desired -> desired.getId().equals(currentRoleGroup.getId()));
                if (!shouldKeep) {
                    user.leaveGroup(currentRoleGroup);
                }
            }

            if (rolesCategoryGroup != null && !shouldHaveRolesCategoryMembership) {
                user.leaveGroup(rolesCategoryGroup);
            }

            if (!shouldHaveNodeMembership) {
                user.leaveGroup(nodeGroup);
            }
        }
    }

    private void joinMissingMemberships(RealmModel realm,
            UserModel user,
            Map<String, List<MidataRole>> rolesByGroupId,
            MapperConfig config) {

        for (Map.Entry<String, List<MidataRole>> entry : rolesByGroupId.entrySet()) {
            String groupId = entry.getKey();
            List<MidataRole> rolesForGroupId = entry.getValue();

            GroupModel nodeGroup = findNodeGroupByGroupId(realm, groupId, config);
            if (nodeGroup == null) {
                LOGGER.fine("Midata-Group-Mapper: No matching node group found for group ID: " + groupId);
                continue;
            }

            if (config.assignUserToGroupNode) {
                user.joinGroup(nodeGroup);
            }

            GroupModel rolesCategoryGroup = findRolesCategoryGroup(nodeGroup);
            if (rolesCategoryGroup == null) {
                continue;
            }

            Set<String> desiredRoleValues = rolesForGroupId.stream()
                    .map(MidataRole::getRole)
                    .collect(Collectors.toSet());

            List<GroupModel> matchingRoleGroups = findRoleGroups(rolesCategoryGroup)
                    .filter(group -> desiredRoleValues.contains(group.getFirstAttribute("role_value")))
                    .collect(Collectors.toList());

            if (config.assignUserToRolesWithNoRoleType && matchingRoleGroups.isEmpty()) {
                user.joinGroup(rolesCategoryGroup);
            } else {
                matchingRoleGroups.forEach(user::joinGroup);
                user.leaveGroup(rolesCategoryGroup);
            }
        }
    }

    /**
     * Assigns the user to every collection group for which they have one of the collection_roles in the
     * group owning the collection or in any group below it, and removes them from all other collections.
     */
    private void syncCollectionMemberships(RealmModel realm, UserModel user,
            Map<String, List<MidataRole>> rolesByGroupId, MapperConfig config) {

        List<GroupModel> collectionGroups = realm.getGroupsStream()
                .filter(group -> "collection".equals(group.getFirstAttribute("node_kind")))
                .filter(group -> isUnderConfiguredRoot(group, config.groupRootPath))
                .collect(Collectors.toList());

        Map<String, Set<String>> groupIdsBelowByKeycloakId = new HashMap<>();
        Set<String> desiredCollectionIds = new HashSet<>();

        for (GroupModel collectionGroup : collectionGroups) {
            GroupModel ownerGroup = findOwningRealGroup(collectionGroup);
            if (ownerGroup == null) {
                LOGGER.warning("Midata-Group-Mapper: Collection group without owning group: "
                        + getGroupPath(collectionGroup));
                continue;
            }

            Set<String> collectionRoles = collectionGroup.getAttributeStream("collection_roles")
                    .collect(Collectors.toSet());
            Set<String> groupIdsBelow = groupIdsBelowByKeycloakId.computeIfAbsent(ownerGroup.getId(),
                    key -> collectRealGroupIds(ownerGroup, new HashSet<>()));

            boolean hasMatchingRole = groupIdsBelow.stream()
                    .flatMap(groupId -> rolesByGroupId.getOrDefault(groupId, List.of()).stream())
                    .anyMatch(role -> collectionRoles.contains(role.getRole()));

            if (hasMatchingRole) {
                desiredCollectionIds.add(collectionGroup.getId());
            }
        }

        LOGGER.info("Midata-Group-Mapper: Found " + desiredCollectionIds.size() + " collection groups for user");

        user.getGroupsStream()
                .filter(group -> "collection".equals(group.getFirstAttribute("node_kind")))
                .filter(group -> isUnderConfiguredRoot(group, config.groupRootPath))
                .filter(group -> !desiredCollectionIds.contains(group.getId()))
                .collect(Collectors.toList())
                .forEach(user::leaveGroup);

        collectionGroups.stream()
                .filter(group -> desiredCollectionIds.contains(group.getId()))
                .forEach(user::joinGroup);
    }

    private GroupModel findOwningRealGroup(GroupModel group) {
        GroupModel parent = group.getParent();
        while (parent != null && !"real".equals(parent.getFirstAttribute("node_kind"))) {
            parent = parent.getParent();
        }
        return parent;
    }

    /**
     * Collects the Midata group ids of the given real group and all real groups below it.
     * Category folders are traversed, roles, events and collections are skipped.
     */
    private Set<String> collectRealGroupIds(GroupModel group, Set<String> groupIds) {
        if ("real".equals(group.getFirstAttribute("node_kind")) && hasAttribute(group, "group_id")) {
            groupIds.add(group.getFirstAttribute("group_id"));
        }

        group.getSubGroupsStream()
                .filter(subGroup -> "real".equals(subGroup.getFirstAttribute("node_kind"))
                        || ("category".equals(subGroup.getFirstAttribute("node_kind"))
                                && !Set.of("roles", "events", "collections")
                                        .contains(subGroup.getFirstAttribute("category_key"))))
                .forEach(subGroup -> collectRealGroupIds(subGroup, groupIds));

        return groupIds;
    }

    private void syncEventMemberships(RealmModel realm, UserModel user, MapperConfig config,
            String externalUserId, String userAccessToken) {
        LOGGER.info("Start Event Sync for userId: " + externalUserId);
        if (externalUserId == null || externalUserId.isBlank()) {
            LOGGER.warning("Midata-Group-Mapper: Skipping event sync because external user id is missing");
            return;
        }

        Map<String, GroupModel> eventGroupsByEventId = realm.getGroupsStream()
                .filter(group -> "event".equals(group.getFirstAttribute("node_kind")))
                .filter(group -> hasAttribute(group, "event_id"))
                .filter(group -> isUnderConfiguredRoot(group, config.groupRootPath))
                .collect(Collectors.toMap(
                        group -> group.getFirstAttribute("event_id"),
                        group -> group,
                        (first, second) -> first,
                        LinkedHashMap::new));

        Map<String, Set<String>> roleTypesByEventId;
        if (eventGroupsByEventId.isEmpty()) {
            roleTypesByEventId = Map.of();
        } else {
            try {
                roleTypesByEventId = fetchEventRoleTypes(config, userAccessToken, externalUserId,
                        eventGroupsByEventId.keySet());
            } catch (IOException | InterruptedException | RuntimeException e) {
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                // Keep the current event memberships instead of removing them because of an API failure
                LOGGER.warning("Midata-Group-Mapper: Skipping event sync, could not fetch event participations: "
                        + e.getMessage());
                return;
            }
        }

        List<GroupModel> desiredEventSubGroups = roleTypesByEventId.entrySet().stream()
                .filter(entry -> eventGroupsByEventId.containsKey(entry.getKey()))
                .flatMap(entry -> eventGroupsByEventId.get(entry.getKey()).getSubGroupsStream()
                        .filter(subGroup -> "category".equals(subGroup.getFirstAttribute("node_kind")))
                        .filter(subGroup -> subGroup.getAttributeStream("event_roles")
                                .anyMatch(entry.getValue()::contains)))
                .collect(Collectors.toList());

        LOGGER.info("Found " + desiredEventSubGroups.size() + " event subgroups for userId: " + externalUserId);
        Set<String> desiredEventSubGroupIds = desiredEventSubGroups.stream()
                .map(GroupModel::getId)
                .collect(Collectors.toSet());

        List<GroupModel> currentEventSubGroups = user.getGroupsStream()
                .filter(group -> isDirectChildOfEventGroupUnderRoot(group, config.groupRootPath))
                .collect(Collectors.toList());
        for (GroupModel currentGroup : currentEventSubGroups) {
            if (!desiredEventSubGroupIds.contains(currentGroup.getId())) {
                user.leaveGroup(currentGroup);
            }
        }

        desiredEventSubGroups.forEach(user::joinGroup);
    }

    /**
     * Fetches the active participations of the given person in the given events from
     * /api/event_participations and returns the event role types per event id.
     */
    private Map<String, Set<String>> fetchEventRoleTypes(MapperConfig config, String userAccessToken,
            String participantId, Set<String> eventIds) throws IOException, InterruptedException {

        if (config.midataApiUrl == null || config.midataApiUrl.isBlank()) {
            throw new IllegalStateException("Midata API URL is not configured");
        }

        Map<String, Set<String>> roleTypesByEventId = new HashMap<>();
        for (int page = 1;; page++) {
            String query = String.join("&",
                    queryParam("filter[participant_id][eq]", participantId),
                    queryParam("filter[participant_type][eq]", "Person"),
                    queryParam("filter[event_id][eq]", String.join(",", eventIds)),
                    queryParam("include", "roles"),
                    queryParam("page[size]", String.valueOf(MIDATA_PAGE_SIZE)),
                    queryParam("page[number]", String.valueOf(page)));

            JsonNode body = getMidataJson(config, userAccessToken, "/api/event_participations?" + query);

            Map<String, String> roleTypesById = new HashMap<>();
            for (JsonNode included : body.path("included")) {
                if ("event_roles".equals(included.path("type").asText())) {
                    roleTypesById.put(included.path("id").asText(),
                            included.path("attributes").path("type").asText(null));
                }
            }

            JsonNode participations = body.path("data");
            for (JsonNode participation : participations) {
                String eventId = participation.path("attributes").path("event_id").asText(null);
                if (eventId == null) {
                    continue;
                }

                Set<String> roleTypes = roleTypesByEventId.computeIfAbsent(eventId, key -> new HashSet<>());
                for (JsonNode roleRef : participation.path("relationships").path("roles").path("data")) {
                    String roleType = roleTypesById.get(roleRef.path("id").asText());
                    if (roleType != null) {
                        roleTypes.add(roleType);
                    }
                }
            }

            if (participations.size() < MIDATA_PAGE_SIZE) {
                return roleTypesByEventId;
            }
        }
    }

    private JsonNode getMidataJson(MapperConfig config, String userAccessToken, String pathAndQuery)
            throws IOException, InterruptedException {

        HttpRequest.Builder request = HttpRequest.newBuilder()
                .uri(URI.create(config.midataApiUrl.replaceAll("/+$", "") + pathAndQuery))
                .timeout(MIDATA_REQUEST_TIMEOUT)
                .header("Accept", "application/vnd.api+json")
                .GET();

        if (config.midataApiToken != null && !config.midataApiToken.isBlank()) {
            request.header("X-Token", config.midataApiToken);
        } else if (userAccessToken != null && !userAccessToken.isBlank()) {
            request.header("Authorization", "Bearer " + userAccessToken);
        } else {
            throw new IllegalStateException("Neither a Midata service token nor a user access token is available");
        }

        HttpResponse<String> response = HTTP_CLIENT.send(request.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Midata API returned HTTP " + response.statusCode() + ": " + response.body());
        }

        return OBJECT_MAPPER.readTree(response.body());
    }

    private static String queryParam(String name, String value) {
        return URLEncoder.encode(name, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private boolean isDirectChildOfEventGroupUnderRoot(GroupModel group, String groupRootPath) {
        GroupModel parent = group.getParent();
        return parent != null
                && "event".equals(parent.getFirstAttribute("node_kind"))
                && isUnderConfiguredRoot(parent, groupRootPath);
    }

    private GroupModel findNodeGroupByGroupId(RealmModel realm, String groupId, MapperConfig config) {
        return realm.getGroupsStream()
                .filter(group -> groupId.equals(group.getFirstAttribute("group_id")))
                .filter(group -> "real".equals(group.getFirstAttribute("node_kind")))
                .filter(group -> isUnderConfiguredRoot(group, config.groupRootPath))
                .findFirst()
                .orElse(null);
    }

    private GroupModel findRolesCategoryGroup(GroupModel nodeGroup) {
        return nodeGroup.getSubGroupsStream()
                .filter(group -> "category".equals(group.getFirstAttribute("node_kind")))
                .filter(group -> "roles".equals(group.getFirstAttribute("category_key")))
                .filter(group -> nodeGroup.getId().equals(group.getParentId()))
                .findFirst()
                .orElse(null);
    }

    private Stream<GroupModel> findRoleGroups(GroupModel rolesCategoryGroup) {
        if (rolesCategoryGroup == null) {
            return Stream.empty();
        }

        return rolesCategoryGroup.getSubGroupsStream()
                .filter(group -> "role".equals(group.getFirstAttribute("node_kind")));
    }

    private boolean hasAttribute(GroupModel group, String attributeName) {
        return group.getFirstAttribute(attributeName) != null;
    }

    private boolean isUnderConfiguredRoot(GroupModel group, String groupRootPath) {
        return groupRootPath == null || groupRootPath.isBlank() || getGroupPath(group).startsWith(groupRootPath);
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
        return "Maps Midata group memberships to Keycloak groups, with optional blacklist filtering.";
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
        LOGGER.info("Midata-Group-Mapper [" + phase + "]"
                + " mapperId=" + mapperModel.getId()
                + ", mapperName=" + mapperModel.getName()
                + ", providerId=" + mapperModel.getIdentityProviderMapper()
                + ", idpAlias=" + mapperModel.getIdentityProviderAlias()
                + ", syncMode=" + mapperModel.getSyncMode()
                + ", config=" + mapperModel.getConfig()
                + ", kcIdpAliasFromContext=" + context.getIdpConfig().getAlias());
    }

    private static final class MapperConfig {
        private final Set<String> blacklist;
        private final String groupRootPath;
        private final boolean assignUserToGroupNode;
        private final boolean assignUserToRolesWithNoRoleType;
        private final String midataApiUrl;
        private final String midataApiToken;

        private MapperConfig(Set<String> blacklist, String groupRootPath,
                boolean assignUserToGroupNode, boolean assignUserToRolesWithNoRoleType,
                String midataApiUrl, String midataApiToken) {
            this.blacklist = blacklist;
            this.groupRootPath = groupRootPath;
            this.assignUserToGroupNode = assignUserToGroupNode;
            this.assignUserToRolesWithNoRoleType = assignUserToRolesWithNoRoleType;
            this.midataApiUrl = midataApiUrl;
            this.midataApiToken = midataApiToken;
        }

        private static MapperConfig from(IdentityProviderMapperModel mapperModel) {
            String blacklistConfig = mapperModel.getConfig().get(CONF_BLACKLIST);

            Set<String> blacklist = blacklistConfig == null || blacklistConfig.isBlank()
                    ? Set.of()
                    : Arrays.stream(blacklistConfig.split(","))
                            .map(String::trim)
                            .filter(value -> !value.isEmpty())
                            .collect(Collectors.toSet());

            String groupRootPath = mapperModel.getConfig().get(CONF_GROUP_ROOT_PATH);

            boolean assignUserToGroupNode = Boolean.parseBoolean(
                    mapperModel.getConfig().getOrDefault(CONF_ASSIGN_USER_TO_GROUP_NODE, "true"));

            boolean assignUserToRolesWithNoRoleType = Boolean.parseBoolean(
                    mapperModel.getConfig().getOrDefault(CONF_ASSIGN_USER_TO_ROLES_WITH_NO_ROLE_TYPE, "false"));

            String midataApiUrl = mapperModel.getConfig().getOrDefault(CONF_MIDATA_API_URL, "https://db.scout.ch");
            String midataApiToken = mapperModel.getConfig().get(CONF_MIDATA_API_TOKEN);

            return new MapperConfig(
                    blacklist,
                    groupRootPath,
                    assignUserToGroupNode,
                    assignUserToRolesWithNoRoleType,
                    midataApiUrl,
                    midataApiToken);
        }
    }
}