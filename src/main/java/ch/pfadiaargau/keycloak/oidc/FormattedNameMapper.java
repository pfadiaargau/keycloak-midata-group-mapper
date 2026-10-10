package ch.pfadiaargau.keycloak.oidc;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
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
 * Builds a string claim from a template of user fields and attributes.
 *
 *   ${firstName} ${lastName}[ / ${nickname}]
 *     -> "Fynn Westerath / Norde"   (with nickname)
 *     -> "Fynn Westerath"           (without nickname: the [...] part is dropped)
 *
 * Placeholders: ${firstName}, ${lastName}, ${email}, ${username}, otherwise a user attribute.
 * A [...] segment is omitted if any placeholder inside it is empty.
 *
 * Register in META-INF/services/org.keycloak.protocol.ProtocolMapper
 */
public class FormattedNameMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "formatted-name-mapper";
    static final String CFG_TEMPLATE = "template";
    static final String DEF_TEMPLATE = "${firstName} ${lastName}[ / ${nickname}]";

    private static final Pattern SEGMENT = Pattern.compile("\\[([^\\[\\]]*)]");
    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]+)}");

    private static final List<ProviderConfigProperty> CONFIG = new ArrayList<>(
            ProviderConfigurationBuilder.create()
                .property().name(CFG_TEMPLATE).label("Template")
                    .helpText("${firstName}, ${lastName}, ${email}, ${username} or ${<user attribute>}. "
                            + "A [...] part is dropped if a placeholder inside it is empty.")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(DEF_TEMPLATE).add()
                .build());

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(CONFIG);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG, FormattedNameMapper.class);
    }

    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "Formatted Name"; }
    @Override public String getDisplayCategory() { return TOKEN_MAPPER_CATEGORY; }
    @Override public String getHelpText() { return "Builds a claim from a template of user fields and attributes."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return CONFIG; }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel model, UserSessionModel userSession,
                            KeycloakSession session, ClientSessionContext ctx) {
        String claim = model.getConfig().get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);
        if (claim == null || claim.isBlank()) return;
        String template = model.getConfig().getOrDefault(CFG_TEMPLATE, DEF_TEMPLATE);
        if (template == null || template.isBlank()) template = DEF_TEMPLATE;

        UserModel user = userSession.getUser();

        // Optional segments first: keep only if all their placeholders have a value
        Matcher seg = SEGMENT.matcher(template);
        StringBuilder sb = new StringBuilder();
        while (seg.find()) {
            String inner = seg.group(1);
            String filled = fill(inner, user, true);
            seg.appendReplacement(sb, Matcher.quoteReplacement(filled == null ? "" : filled));
        }
        seg.appendTail(sb);

        String value = fill(sb.toString(), user, false).replaceAll("\\s+", " ").trim();
        if (!value.isEmpty()) token.getOtherClaims().put(claim, value);
    }

    /** Replaces placeholders; with {@code strict}, returns null as soon as one is empty. */
    private static String fill(String text, UserModel user, boolean strict) {
        Matcher m = PLACEHOLDER.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String v = resolve(m.group(1).trim(), user);
            if (v == null || v.isBlank()) {
                if (strict) return null;
                v = "";
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(v.trim()));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String resolve(String key, UserModel user) {
        return switch (key) {
            case "firstName" -> user.getFirstName();
            case "lastName" -> user.getLastName();
            case "email" -> user.getEmail();
            case "username" -> user.getUsername();
            default -> user.getFirstAttribute(key);
        };
    }
}