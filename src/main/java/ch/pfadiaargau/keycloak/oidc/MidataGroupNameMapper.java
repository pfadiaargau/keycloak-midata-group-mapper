package ch.pfadiaargau.keycloak.oidc;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.IDToken;

/**
 * Emits group names for one client, derived from the user's MiData group memberships plus the
 * client's manually assigned roles, so the Abteilung part needs no Keycloak roles at all.
 *
 * 1. Raw roles (toggle "emit_raw_roles")
 *      Abteilung role           -> <P>_<RoleName>                    e.g. Hochwacht_Coach
 *      Kantonalverband role     -> <KvP>_<RoleName>                  e.g. PfadiAargau_Kantonsleitung
 *
 * 2. Stufen and units (Meute, Fähnli, Rudel, ...)
 *      Stufe                    -> <P>_<Stufe>_Leitende | _TN        e.g. Hochwacht_Wolfsstufe_TN
 *      Unit (toggle "emit_units", off by default)
 *                               -> <P>_<Stufe>_<Unit>_Leitende | _TN e.g. Adler_Wolfsstufe_Meute_Tavi_TN
 *    Leader = has one of "stufe_leader_roles" in that node or below it. Members of non-Stufe
 *    nodes below a Stufe (Inaktiv, Warteliste, ...) are ignored.
 *    Toggles "emit_stufe_leaders" / "emit_stufe_tn" switch off the _Leitende / _TN names (Stufen and
 *    units), e.g. when collections provide them. A leader never falls back to _TN.
 *
 * 3. Role groups ("role_groups"): scope:Name=Role1|Role2;...   scope = stufe|abteilung|kantonalverband
 *      stufe:Stufenleitung=Adressverwaltung|Einheitsleitung -> Hochwacht_Wolfsstufe_Stufenleitung
 *
 * 4. Grouped groups ("grouped_groups"): Name=Glob1|Glob2;...  globs on the part after "<P>_",
 *    evaluated in order (later entries may use earlier ones). Empty by default, use collections instead.
 *      Stufenleitende=*_Stufenleitung -> Hochwacht_Stufenleitende
 *
 * 5. Events (toggle "emit_events"): member of a category below a node_kind=event group
 *      -> <EventName>_<Category>   e.g. AG251-26_Leitung, AG251-26_TN ("event_category_aliases")
 *
 * 6. Member types ("member_types"): any member of a node of that group_type inside an Abteilung
 *      Group::Elternrat=Elternrat -> Hochwacht_Elternrat
 *
 * 6b. Collections (toggle "emit_collections", off by default): member of a node_kind=collection
 *    group -> <P>_<Collection> with <P> of the group owning the collection
 *      e.g. PfadiAargau_Leitende, Hochwacht_Leitende_Biberstufe
 *    Added after the grouped groups, so collection names never feed grouped-group globs.
 *
 * 7. Client roles (toggle "include_client_roles"): the requesting client's roles from direct
 *    user mappings and from every group the user is in plus its parents (composites expanded),
 *    emitted under their own name, e.g. KaLei, Vorstand. Attach Gremium roles to the Gremium's
 *    "Rollen" folder so they don't leak into nested Gremien.
 *
 * Ignored roles ("ignored_roles", last role segment, default Passivmitglied,Ehrenmitglied) are
 * skipped completely: someone with only those roles gets no groups and cannot log in.
 *
 * 8. Quota (optional, "quota_claim"): users whose groups ALL match "participant_groups"
 *    (default *_TN: Stufe TN and event Teilnehmende) get "participant_quota" (default "0 B"),
 *    everyone else "default_quota" (default "default" = Nextcloud default quota).
 *    In Nextcloud user_oidc: --mapping-quota=<quota_claim>
 *
 * Memberships count from role subgroups, real nodes and "Rollen" folders (roles without own
 * subgroup), so it works with assign_user_to_group_node off.
 * Grouped groups with "kantonalverband:" emit <KvP>_<Name> from matches under any prefix.
 *
 * <P> = group attribute (default "nextcloud_prefix") on the Abteilung / Kantonalverband node,
 * falling back to the sanitized group name. Everything is merged into an existing claim.
 *
 * Register in META-INF/services/org.keycloak.protocol.ProtocolMapper
 */
public class MidataGroupNameMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "midata-group-name-mapper";

    static final String ABTEILUNG = "Group::Abteilung";
    static final String KANTONALVERBAND = "Group::Kantonalverband";

    static final String SCOPE_STUFE = "stufe";
    static final String SCOPE_ABTEILUNG = "abteilung";
    static final String SCOPE_KV = "kantonalverband";

    static final String CFG_PREFIX_ATTR = "prefix_attribute";
    static final String CFG_STUFEN = "stufen";
    static final String CFG_STUFENLEITUNG = "stufenleitung_roles";
    static final String CFG_LEADER_ROLES = "stufe_leader_roles";
    static final String CFG_ROLE_ALIASES = "role_aliases";
    static final String CFG_LEADER_SUFFIX = "leader_suffix";
    static final String CFG_TN_SUFFIX = "tn_suffix";
    static final String CFG_EMIT_RAW_ROLES = "emit_raw_roles";
    static final String CFG_EMIT_UNITS = "emit_units";
    static final String CFG_EMIT_STUFE_LEADERS = "emit_stufe_leaders";
    static final String CFG_EMIT_STUFE_TN = "emit_stufe_tn";
    static final String CFG_ROLE_GROUPS = "role_groups";
    static final String CFG_GROUPED_GROUPS = "grouped_groups";
    static final String CFG_MEMBER_TYPES = "member_types";
    static final String CFG_EMIT_EVENTS = "emit_events";
    static final String CFG_EMIT_COLLECTIONS = "emit_collections";
    static final String CFG_EVENT_ALIASES = "event_category_aliases";
    static final String CFG_INCLUDE_CLIENT_ROLES = "include_client_roles";
    static final String CFG_EXCLUDED_CLIENT_ROLES = "excluded_client_roles";
    static final String CFG_IGNORED_ROLES = "ignored_roles";
    static final String CFG_QUOTA_CLAIM = "quota_claim";
    static final String CFG_PARTICIPANT_GROUPS = "participant_groups";
    static final String CFG_PARTICIPANT_QUOTA = "participant_quota";
    static final String CFG_DEFAULT_QUOTA = "default_quota";

    // Defaults: verify role values against model/roles in midata-roles-importer.
    static final String DEF_PREFIX_ATTR = "nextcloud_prefix";
    static final String DEF_STUFEN =
            "Group::Biber=Biberstufe,Group::Woelfe=Wolfsstufe,Group::Pfadi=Pfadistufe,"
          + "Group::Pio=Piostufe,Group::AbteilungsRover=Roverstufe,Group::Pta=PTA";
    static final String DEF_STUFENLEITUNG =
            "Group::Abteilung::StufenleitungBiber=Group::Biber,"
          + "Group::Abteilung::StufenleitungWoelfe=Group::Woelfe,"
          + "Group::Abteilung::StufenleitungPfadi=Group::Pfadi,"
          + "Group::Abteilung::StufenleitungPio=Group::Pio,"
          + "Group::Abteilung::StufenleitungRover=Group::AbteilungsRover,"
          + "Group::Abteilung::StufenleitungPta=Group::Pta";
    static final String DEF_LEADER_ROLES = "Einheitsleitung,Mitleitung";
    static final String DEF_ROLE_ALIASES = "Abteilungsleitung=Abteilungsleiter";
    static final String DEF_LEADER_SUFFIX = "_Leitende";
    static final String DEF_TN_SUFFIX = "_TN";
    static final String DEF_ROLE_GROUPS = "stufe:Stufenleitung=Adressverwaltung|Einheitsleitung";
    static final String DEF_GROUPED_GROUPS = "";
    static final String DEF_EVENT_ALIASES = "Teilnehmende=TN";
    static final String DEF_MEMBER_TYPES = "Group::Elternrat=Elternrat";
    static final String DEF_IGNORED_ROLES = "Passivmitglied,Ehrenmitglied";
    static final String DEF_PARTICIPANT_GROUPS = "*_TN";
    static final String DEF_PARTICIPANT_QUOTA = "0 B";
    static final String DEF_DEFAULT_QUOTA = "default";

    private static final List<ProviderConfigProperty> CONFIG = new ArrayList<>(
            ProviderConfigurationBuilder.create()
                .property().name(CFG_PREFIX_ATTR).label("Prefix attribute")
                    .helpText("Group attribute on Abteilung/Kantonalverband nodes holding the name prefix. "
                            + "Falls back to the sanitized group name.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_PREFIX_ATTR).add()
                .property().name(CFG_STUFEN).label("Stufen (group_type=Name, comma-separated)")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_STUFEN).add()
                .property().name(CFG_STUFENLEITUNG).label("Abteilung Stufenleitung roles (role_value=Stufe group_type)")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_STUFENLEITUNG).add()
                .property().name(CFG_LEADER_ROLES).label("Leader roles inside a Stufe (last role segment)")
                    .helpText("Decides _Leitende vs. _TN.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_LEADER_ROLES).add()
                .property().name(CFG_ROLE_ALIASES).label("Role name aliases (RoleName=GroupSuffix)")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_ROLE_ALIASES).add()
                .property().name(CFG_LEADER_SUFFIX).label("Leader suffix")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_LEADER_SUFFIX).add()
                .property().name(CFG_TN_SUFFIX).label("Participant suffix")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_TN_SUFFIX).add()
                .property().name(CFG_EMIT_RAW_ROLES).label("Emit raw role names")
                    .helpText("Emit <P>_<RoleName> for every Abteilung/Kantonalverband role.")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("true").add()
                .property().name(CFG_EMIT_UNITS).label("Emit units")
                    .helpText("Emit <P>_<Stufe>_<Unit>_Leitende/_TN for Meuten, Fähnli, Rudel, ...")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("false").add()
                .property().name(CFG_EMIT_STUFE_LEADERS).label("Emit Stufe leaders")
                    .helpText("Emit <P>_<Stufe>_Leitende (and unit _Leitende). Turn off when collections "
                            + "provide these names.")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("true").add()
                .property().name(CFG_EMIT_STUFE_TN).label("Emit Stufe TN")
                    .helpText("Emit <P>_<Stufe>_TN (and unit _TN). Users whose only groups are TN groups "
                            + "get no groups at all when this is off and cannot log in.")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("true").add()
                .property().name(CFG_ROLE_GROUPS).label("Role groups")
                    .helpText("scope:Name=Role1|Role2 entries separated by ';'. "
                            + "scope = stufe | abteilung | kantonalverband.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_ROLE_GROUPS).add()
                .property().name(CFG_GROUPED_GROUPS).label("Grouped groups")
                    .helpText("[kantonalverband:]Name=Glob1|Glob2 entries separated by ';', matched after "
                            + "'<Prefix>_'. Evaluated in order. With 'kantonalverband:' a match under any "
                            + "prefix emits <KvPrefix>_<Name>.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_GROUPED_GROUPS).add()
                .property().name(CFG_MEMBER_TYPES).label("Member types (group_type=Name)")
                    .helpText("Every member of a node of this type inside an Abteilung gets <P>_<Name>, "
                            + "e.g. Group::Elternrat=Elternrat.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_MEMBER_TYPES).add()
                .property().name(CFG_EMIT_EVENTS).label("Emit events")
                    .helpText("Emit <EventName>_<Category> for event participant categories.")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("true").add()
                .property().name(CFG_EMIT_COLLECTIONS).label("Emit collections")
                    .helpText("Emit <P>_<Collection> for collection groups (Sammlungen), with <P> of the group "
                            + "owning the collection, e.g. PfadiAargau_Leitende.")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("false").add()
                .property().name(CFG_EVENT_ALIASES).label("Event category aliases (CategoryName=Suffix)")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_EVENT_ALIASES).add()
                .property().name(CFG_INCLUDE_CLIENT_ROLES).label("Include client roles")
                    .helpText("Add the requesting client's roles (direct, via groups and parent groups).")
                    .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("true").add()
                .property().name(CFG_EXCLUDED_CLIENT_ROLES).label("Excluded client roles")
                    .helpText("Comma-separated client roles not to emit, e.g. an access-gate role.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue("").add()
                .property().name(CFG_IGNORED_ROLES).label("Ignored roles (last role segment)")
                    .helpText("Comma-separated MiData roles that give no group at all, "
                            + "e.g. Passivmitglied,Ehrenmitglied. Users with only these roles cannot log in.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_IGNORED_ROLES).add()
                .property().name(CFG_QUOTA_CLAIM).label("Quota claim name")
                    .helpText("Empty = no quota claim. Otherwise e.g. 'quota' and in user_oidc "
                            + "--mapping-quota=quota.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue("").add()
                .property().name(CFG_PARTICIPANT_GROUPS).label("Participant groups (globs, '|'-separated)")
                    .helpText("A user whose emitted groups ALL match one of these gets the participant quota.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_PARTICIPANT_GROUPS).add()
                .property().name(CFG_PARTICIPANT_QUOTA).label("Participant quota")
                    .helpText("e.g. '0 B' (no personal space) or '100 MB'.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_PARTICIPANT_QUOTA).add()
                .property().name(CFG_DEFAULT_QUOTA).label("Quota for everyone else")
                    .helpText("'default' = Nextcloud default quota, 'none' = unlimited, or e.g. '10 GB'.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_DEFAULT_QUOTA).add()
                .build());

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(CONFIG);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG, MidataGroupNameMapper.class);
    }

    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "MiData Group Names"; }
    @Override public String getDisplayCategory() { return TOKEN_MAPPER_CATEGORY; }
    @Override public String getHelpText() {
        return "Derives group names from MiData memberships (roles, Stufen, units, events, role groups, "
             + "grouped groups, collections), adds the client's roles and merges everything into the claim.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return CONFIG; }

    /** Run after other mappers so the merge sees their claim values (higher = later). */
    @Override public int getPriority() { return 100; }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel model, UserSessionModel userSession,
                            KeycloakSession session, ClientSessionContext ctx) {
        Cfg cfg = new Cfg(model.getConfig());
        Result r = new Result();
        UserModel user = userSession.getUser();
        List<GroupModel> groups = user.getGroupsStream().toList();

        groups.forEach(g -> collect(g, cfg, r));
        r.stufen.forEach((base, leader) -> addStufeName(base, leader, cfg, r));
        r.units.forEach((base, leader) -> addStufeName(base, leader, cfg, r));
        applyGroupedGroups(cfg, r);
        r.names.addAll(r.collections);

        if (cfg.includeClientRoles) {
            addClientRoles(user, groups, ctx.getClientSession().getClient(), cfg, r);
        }

        if (r.names.isEmpty()) return; // no Pfadi Aargau group: no claims, login is refused

        if (!cfg.quotaClaim.isBlank()) {
            boolean participantOnly = r.names.stream()
                    .allMatch(n -> cfg.participantGroups.stream().anyMatch(p -> p.matcher(n).matches()));
            token.getOtherClaims().put(cfg.quotaClaim, participantOnly ? cfg.participantQuota : cfg.defaultQuota);
        }

        String claim = model.getConfig().get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);
        if (claim == null || claim.isBlank()) return;
        merge(token, claim, r.names);
    }

    private static void addStufeName(String base, boolean leader, Cfg cfg, Result r) {
        if (leader ? cfg.emitStufeLeaders : cfg.emitStufeTn) {
            r.names.add(base + (leader ? cfg.leaderSuffix : cfg.tnSuffix));
        }
    }

    private void collect(GroupModel g, Cfg cfg, Result r) {
        String kind = g.getFirstAttribute("node_kind");
        if (kind == null) return;
        if ("collection".equals(kind)) {
            GroupModel owner = firstReal(g);
            if (cfg.emitCollections && owner != null) {
                r.collections.add(prefix(owner, cfg) + "_" + sanitize(g.getName()));
            }
            return;
        }
        if ("role".equals(kind)) {
            String rv = g.getFirstAttribute("role_value");
            if (rv != null && cfg.ignoredRoles.contains(lastSegment(rv))) return;
        }

        if ("category".equals(kind)) {
            GroupModel parent = g.getParent();
            // Events: Anlässe/<Event>/<Category>
            if (parent != null && "event".equals(parent.getFirstAttribute("node_kind"))) {
                if (cfg.emitEvents) r.names.add(sanitize(parent.getName()) + "_" + cfg.eventAlias(g.getName()));
                return;
            }
            // A "Rollen" folder membership (roles without own subgroup, e.g. Wolf, Elternrat member)
            // counts as plain membership of the group the folder belongs to.
            if (!"roles".equals(g.getFirstAttribute("category_key"))) return;
        } else if (!"role".equals(kind) && !"real".equals(kind)) {
            return;
        }

        // Every membership below the Kantonalverband makes its prefix available for
        // kantonalverband-scoped grouped groups (PfadiAargau_Leitende).
        GroupModel kvNode = findReal(g, KANTONALVERBAND);
        if (kvNode != null) r.kvPrefixes.add(prefix(kvNode, cfg));

        GroupModel abteilung = findReal(g, ABTEILUNG);
        // The MiData group the membership belongs to (role node / Rollen folder -> real group)
        GroupModel owner = firstReal(g);
        List<GroupModel> chain = abteilung == null || owner == null ? List.of() : stufeChain(owner, cfg);

        // Member types: any member of e.g. an Elternrat node -> <P>_Elternrat
        if (abteilung != null && owner != null) {
            String memberName = cfg.memberTypes.get(owner.getFirstAttribute("group_type"));
            if (memberName != null) {
                String p = prefix(abteilung, cfg);
                r.prefixes.add(p);
                r.names.add(p + "_" + memberName);
            }
        }

        if ("role".equals(kind)) {
            String roleValue = g.getFirstAttribute("role_value");
            String ownerType = g.getFirstAttribute("group_type");
            if (roleValue == null || ownerType == null) return;
            String roleName = lastSegment(roleValue);

            if (!chain.isEmpty()) {
                String p = prefix(abteilung, cfg);
                r.prefixes.add(p);
                String stufeBase = markStufe(p, chain, cfg.leaderRoles.contains(roleName), cfg, r);
                addRoleGroups(cfg, SCOPE_STUFE, roleName, stufeBase, r);

            } else if (abteilung != null && ABTEILUNG.equals(ownerType)) {
                String p = prefix(abteilung, cfg);
                r.prefixes.add(p);
                if (cfg.emitRawRoles) r.names.add(p + "_" + cfg.alias(roleName));
                addRoleGroups(cfg, SCOPE_ABTEILUNG, roleName, p, r);
                String stufeType = cfg.stufenleitung.get(roleValue);
                if (stufeType != null && cfg.stufen.containsKey(stufeType)) {
                    r.stufen.merge(p + "_" + cfg.stufen.get(stufeType), true, Boolean::logicalOr);
                }

            } else if (KANTONALVERBAND.equals(ownerType)) {
                GroupModel kv = findReal(g, KANTONALVERBAND);
                if (kv == null) return;
                String p = prefix(kv, cfg);
                r.prefixes.add(p);
                if (cfg.emitRawRoles) r.names.add(p + "_" + cfg.alias(roleName));
                addRoleGroups(cfg, SCOPE_KV, roleName, p, r);
            }

        } else if (!chain.isEmpty()) { // plain member of a Stufe or unit (real node or Rollen folder)
            String p = prefix(abteilung, cfg);
            r.prefixes.add(p);
            markStufe(p, chain, false, cfg, r);
        }
    }

    /**
     * Marks the Stufe (topmost node of the chain) and, if enabled, every unit in the chain.
     * A leader in a unit also counts as leader of all units above it and of the Stufe.
     * Returns the Stufe base name "<P>_<Stufe>".
     */
    private static String markStufe(String p, List<GroupModel> chain, boolean leader, Cfg cfg, Result r) {
        GroupModel top = chain.get(chain.size() - 1);
        String stufeBase = p + "_" + cfg.stufen.get(top.getFirstAttribute("group_type"));
        r.stufen.merge(stufeBase, leader, Boolean::logicalOr);
        if (cfg.emitUnits) {
            for (int i = 0; i < chain.size() - 1; i++) {
                r.units.merge(stufeBase + "_" + sanitize(chain.get(i).getName()), leader, Boolean::logicalOr);
            }
        }
        return stufeBase;
    }

    /**
     * Stufe-type real nodes from {@code owner} upwards, stopping at the Abteilung.
     * Empty if the owner itself is not a Stufe-type node (Inaktiv, Warteliste, ...).
     */
    private static List<GroupModel> stufeChain(GroupModel owner, Cfg cfg) {
        if (!cfg.stufen.containsKey(owner.getFirstAttribute("group_type"))) return List.of();
        List<GroupModel> chain = new ArrayList<>();
        for (GroupModel cur = owner; cur != null; cur = cur.getParent()) {
            if (!"real".equals(cur.getFirstAttribute("node_kind"))) continue;
            String type = cur.getFirstAttribute("group_type");
            if (ABTEILUNG.equals(type)) return chain;
            if (type != null && cfg.stufen.containsKey(type)) chain.add(cur);
        }
        return List.of(); // no Abteilung above: not a Stufe of an Abteilung
    }

    private static void addRoleGroups(Cfg cfg, String scope, String roleName, String base, Result r) {
        for (RoleGroup rg : cfg.roleGroups) {
            if (rg.scope.equals(scope) && rg.roles.contains(roleName)) r.names.add(base + "_" + rg.name);
        }
    }

    /**
     * Prefix scope (default): for every prefix the user has, add <P>_<Name> if a derived name
     * "<P>_<suffix>" matches a member glob.
     * Kantonalverband scope: if a derived name under ANY prefix matches, add <KvP>_<Name>.
     */
    private static void applyGroupedGroups(Cfg cfg, Result r) {
        for (GroupedGroup gg : cfg.groupedGroups) {
            if (SCOPE_KV.equals(gg.scope)) {
                boolean hit = r.prefixes.stream().anyMatch(p -> matches(gg, p, r));
                if (hit) r.kvPrefixes.forEach(kv -> r.names.add(kv + "_" + gg.name));
            } else {
                for (String p : List.copyOf(r.prefixes)) {
                    if (matches(gg, p, r)) r.names.add(p + "_" + gg.name);
                }
            }
        }
    }

    private static boolean matches(GroupedGroup gg, String prefix, Result r) {
        String start = prefix + "_";
        return r.names.stream()
                .filter(n -> n.startsWith(start))
                .map(n -> n.substring(start.length()))
                .anyMatch(s -> gg.members.stream().anyMatch(m -> m.matcher(s).matches()));
    }

    /**
     * Client roles of {@code client}: direct user mappings + every group the user is in and its
     * parents (normal Keycloak inheritance), composites expanded. Attach Gremium roles to the
     * Gremium's "Rollen" folder so they don't leak into nested Gremien.
     */
    private static void addClientRoles(UserModel user, List<GroupModel> groups, ClientModel client, Cfg cfg, Result r) {
        Set<RoleModel> roles = new HashSet<>();
        user.getRoleMappingsStream().forEach(roles::add);
        for (GroupModel g : groups) {
            for (GroupModel cur = g; cur != null; cur = cur.getParent()) {
                cur.getRoleMappingsStream().forEach(roles::add);
            }
        }
        Deque<RoleModel> todo = new ArrayDeque<>(roles);
        while (!todo.isEmpty()) {
            RoleModel role = todo.pop();
            if (role.isComposite()) {
                role.getCompositesStream().filter(roles::add).forEach(todo::push);
            }
        }
        roles.stream()
                .filter(RoleModel::isClientRole)
                .filter(role -> client.getId().equals(role.getContainerId()))
                .map(RoleModel::getName)
                .filter(name -> !cfg.excludedClientRoles.contains(name))
                .forEach(r.names::add);
    }

    /** First ancestor (incl. self) that is a real MiData group of the given type. */
    private static GroupModel findReal(GroupModel g, String type) {
        for (GroupModel cur = g; cur != null; cur = cur.getParent()) {
            if ("real".equals(cur.getFirstAttribute("node_kind")) && type.equals(cur.getFirstAttribute("group_type"))) {
                return cur;
            }
        }
        return null;
    }

    /** First ancestor (incl. self) that is a real MiData group. */
    private static GroupModel firstReal(GroupModel g) {
        for (GroupModel cur = g; cur != null; cur = cur.getParent()) {
            if ("real".equals(cur.getFirstAttribute("node_kind"))) return cur;
        }
        return null;
    }

    private static String prefix(GroupModel node, Cfg cfg) {
        String p = node.getFirstAttribute(cfg.prefixAttr);
        return p != null && !p.isBlank() ? p.trim() : pascalCase(node.getName());
    }

    /** "Pfadi Schöftland Diana von May" -> "PfadiSchoeftlandDianaVonMay" (ASCII, no separators). */
    private static String pascalCase(String s) {
        String ascii = s.replace("ä", "ae").replace("ö", "oe").replace("ü", "ue")
                .replace("Ä", "Ae").replace("Ö", "Oe").replace("Ü", "Ue");
        ascii = java.text.Normalizer.normalize(ascii, java.text.Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "");
        StringBuilder out = new StringBuilder();
        for (String word : ascii.split("[^A-Za-z0-9]+")) {
            if (word.isEmpty()) continue;
            out.append(Character.toUpperCase(word.charAt(0))).append(word.substring(1));
        }
        return out.toString();
    }

    /** Letters/digits/'-' kept, everything else collapsed to '_', no leading/trailing '_'. */
    private static String sanitize(String s) {
        return s.trim().replaceAll("[^\\p{L}\\p{N}-]+", "_").replaceAll("^_+|_+$", "");
    }

    private static String lastSegment(String roleValue) {
        int i = roleValue.lastIndexOf("::");
        return i >= 0 ? roleValue.substring(i + 2) : roleValue;
    }

    private static void merge(IDToken token, String claim, Set<String> names) {
        Set<String> merged = new LinkedHashSet<>();
        Object existing = token.getOtherClaims().get(claim);
        if (existing instanceof Collection<?> c) c.forEach(o -> merged.add(String.valueOf(o)));
        else if (existing != null) merged.add(String.valueOf(existing));
        merged.addAll(names);
        token.getOtherClaims().put(claim, new ArrayList<>(merged));
    }

    /** Per-request working state. */
    private static final class Result {
        final Set<String> names = new TreeSet<>();
        final Map<String, Boolean> stufen = new HashMap<>(); // "<P>_<Stufe>" -> is leader
        final Map<String, Boolean> units = new HashMap<>();  // "<P>_<Stufe>_<Unit>" -> is leader
        final Set<String> prefixes = new LinkedHashSet<>();
        final Set<String> kvPrefixes = new LinkedHashSet<>();
        final Set<String> collections = new TreeSet<>();
    }

    private record RoleGroup(String scope, String name, Set<String> roles) {}
    private record GroupedGroup(String scope, String name, List<Pattern> members) {}

    /** Parsed mapper configuration with defaults. */
    private static final class Cfg {
        final String prefixAttr, leaderSuffix, tnSuffix, quotaClaim, participantQuota, defaultQuota;
        final List<Pattern> participantGroups = new ArrayList<>();
        final boolean emitRawRoles, emitUnits, emitStufeLeaders, emitStufeTn, emitEvents, emitCollections,
                includeClientRoles;
        final Map<String, String> stufen, stufenleitung, aliases, eventAliases, memberTypes;
        final Set<String> leaderRoles, excludedClientRoles, ignoredRoles;
        final List<RoleGroup> roleGroups = new ArrayList<>();
        final List<GroupedGroup> groupedGroups = new ArrayList<>();

        Cfg(Map<String, String> c) {
            prefixAttr = get(c, CFG_PREFIX_ATTR, DEF_PREFIX_ATTR);
            stufen = pairs(get(c, CFG_STUFEN, DEF_STUFEN));
            stufenleitung = pairs(get(c, CFG_STUFENLEITUNG, DEF_STUFENLEITUNG));
            aliases = pairs(get(c, CFG_ROLE_ALIASES, DEF_ROLE_ALIASES));
            eventAliases = pairs(get(c, CFG_EVENT_ALIASES, DEF_EVENT_ALIASES));
            memberTypes = pairs(get(c, CFG_MEMBER_TYPES, DEF_MEMBER_TYPES));
            leaderRoles = new HashSet<>(split(get(c, CFG_LEADER_ROLES, DEF_LEADER_ROLES), ","));
            excludedClientRoles = new HashSet<>(split(get(c, CFG_EXCLUDED_CLIENT_ROLES, ""), ","));
            // explicitly emptied in the admin console = ignore nothing
            ignoredRoles = new HashSet<>(split(c != null && c.containsKey(CFG_IGNORED_ROLES)
                    ? Objects.toString(c.get(CFG_IGNORED_ROLES), "") : DEF_IGNORED_ROLES, ","));
            quotaClaim = get(c, CFG_QUOTA_CLAIM, "").trim();
            participantQuota = get(c, CFG_PARTICIPANT_QUOTA, DEF_PARTICIPANT_QUOTA).trim();
            defaultQuota = get(c, CFG_DEFAULT_QUOTA, DEF_DEFAULT_QUOTA).trim();
            for (String g : split(get(c, CFG_PARTICIPANT_GROUPS, DEF_PARTICIPANT_GROUPS), "\\|")) {
                participantGroups.add(glob(g));
            }
            leaderSuffix = c != null && c.containsKey(CFG_LEADER_SUFFIX) ? c.get(CFG_LEADER_SUFFIX) : DEF_LEADER_SUFFIX;
            tnSuffix = get(c, CFG_TN_SUFFIX, DEF_TN_SUFFIX);
            emitRawRoles = bool(c, CFG_EMIT_RAW_ROLES);
            emitUnits = c != null && Boolean.parseBoolean(c.get(CFG_EMIT_UNITS)); // off unless enabled
            emitStufeLeaders = bool(c, CFG_EMIT_STUFE_LEADERS);
            emitStufeTn = bool(c, CFG_EMIT_STUFE_TN);
            emitEvents = bool(c, CFG_EMIT_EVENTS);
            emitCollections = c != null && Boolean.parseBoolean(c.get(CFG_EMIT_COLLECTIONS)); // off unless enabled
            includeClientRoles = bool(c, CFG_INCLUDE_CLIENT_ROLES);

            for (String entry : split(get(c, CFG_ROLE_GROUPS, DEF_ROLE_GROUPS), ";")) {
                int colon = entry.indexOf(':'), eq = entry.indexOf('=');
                if (colon <= 0 || eq <= colon + 1) continue;
                roleGroups.add(new RoleGroup(
                        entry.substring(0, colon).trim().toLowerCase(Locale.ROOT),
                        entry.substring(colon + 1, eq).trim(),
                        new HashSet<>(split(entry.substring(eq + 1), "\\|"))));
            }
            // [kantonalverband:]Name=Glob1|Glob2;...
            for (String entry : split(get(c, CFG_GROUPED_GROUPS, DEF_GROUPED_GROUPS), ";")) {
                int eq = entry.indexOf('=');
                if (eq <= 0) continue;
                String head = entry.substring(0, eq).trim();
                String scope = "prefix";
                int colon = head.indexOf(':');
                if (colon > 0) {
                    scope = head.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                    head = head.substring(colon + 1).trim();
                }
                List<Pattern> members = new ArrayList<>();
                for (String g : split(entry.substring(eq + 1), "\\|")) members.add(glob(g));
                groupedGroups.add(new GroupedGroup(scope, head, members));
            }
        }

        String alias(String roleName) { return aliases.getOrDefault(roleName, roleName); }
        String eventAlias(String category) { return sanitize(eventAliases.getOrDefault(category, category)); }

        /** Booleans default to true when not configured. */
        private static boolean bool(Map<String, String> c, String key) {
            String v = c == null ? null : c.get(key);
            return v == null || v.isBlank() || Boolean.parseBoolean(v);
        }

        private static String get(Map<String, String> c, String key, String def) {
            String v = c == null ? null : c.get(key);
            return v == null || v.isBlank() ? def : v;
        }

        private static List<String> split(String s, String regex) {
            List<String> out = new ArrayList<>();
            for (String part : s.split(regex)) if (!part.isBlank()) out.add(part.trim());
            return out;
        }

        private static Map<String, String> pairs(String s) {
            Map<String, String> out = new HashMap<>();
            for (String part : split(s, ",")) {
                int i = part.indexOf('=');
                if (i > 0) out.put(part.substring(0, i).trim(), part.substring(i + 1).trim());
            }
            return out;
        }

        /** '*' matches any characters, everything else is literal. */
        private static Pattern glob(String g) {
            String[] parts = g.split("\\*", -1);
            StringBuilder re = new StringBuilder();
            for (int i = 0; i < parts.length; i++) {
                if (i > 0) re.append(".*");
                re.append(Pattern.quote(parts[i]));
            }
            return Pattern.compile(re.toString());
        }
    }
}