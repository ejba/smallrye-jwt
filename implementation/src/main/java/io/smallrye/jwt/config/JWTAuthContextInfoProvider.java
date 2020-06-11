/*
 *   Copyright 2018 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

package io.smallrye.jwt.config;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import org.eclipse.microprofile.config.Config;

import io.smallrye.jwt.KeyFormat;
import io.smallrye.jwt.KeyUtils;
import io.smallrye.jwt.SmallryeJwtUtils;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

/**
 * A CDI provider for the JWTAuthContextInfo that obtains the necessary information from
 * MP config properties.
 */
@Dependent
public class JWTAuthContextInfoProvider {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_SCHEME = "Bearer";
    private static final String NONE = "NONE";
    private static final String DEFAULT_GROUPS_SEPARATOR = " ";

    @Inject
    Config config;

    private Set<String> loaded = new HashSet<>();

    static class JWTAuthConfigProperty {
        static final String MP_JWT_PUBLIC_KEY = "mp.jwt.verify.publickey";
        static final String MP_JWT_ISSUER = "mp.jwt.verify.issuer";
        static final String MP_JWT_LOCATION = "mp.jwt.verify.publickey.location";
        static final String MP_JWT_REQUIRE_ISS = "mp.jwt.verify.requireiss";
        static final String TOKEN_HEADER = "smallrye.jwt.token.header";
        static final String TOKEN_COOKIE = "smallrye.jwt.token.cookie";
        static final String ALWAYS_CHECK_AUTHORIZATION = "smallrye.jwt.always-check-authorization";
        static final String TOKEN_KEY_ID = "smallrye.jwt.token.kid";
        static final String TOKEN_SCHEMES = "smallrye.jwt.token.schemes";
        static final String REQUIRE_NAMED_PRINCIPAL = "smallrye.jwt.require.named-principal";
        static final String DEFAULT_SUB_CLAIM = "smallrye.jwt.claims.sub";
        static final String SUB_PATH = "smallrye.jwt.path.sub";
        static final String DEFAULT_GROUPS_CLAIM = "smallrye.jwt.claims.groups";
        static final String GROUPS_PATH = "smallrye.jwt.path.groups";
        static final String GROUPS_SEPARATOR = "smallrye.jwt.groups-separator";
        static final String EXP_GRACE_PERIOD_SECS = "smallrye.jwt.expiration.grace";
        static final String MAX_TIME_TO_LIVE_SECS = "smallrye.jwt.time-to-live";
        static final String JWKS_REFRESH_INTERVAL = "smallrye.jwt.jwks.refresh-interval";
        static final String FORCED_JWKS_REFRESH_INTERVAL = "smallrye.jwt.jwks.forced-refresh-interval";
        static final String WHITELIST_ALGORITHMS = "smallrye.jwt.whitelist.algorithms";
        static final String SIGNATURE_ALGORITHM = "smallrye.jwt.verify.algorithm";
        static final String KEY_FORMAT = "smallrye.jwt.verify.key-format";
        static final String EXPECTED_AUDIENCE = "smallrye.jwt.verify.aud";
        static final String REQUIRED_CLAIMS = "smallrye.jwt.required.claims";

        public static Set<String> getAllPropertyNames() {
            return new HashSet<>(Arrays.asList(
                    MP_JWT_PUBLIC_KEY,
                    MP_JWT_ISSUER,
                    MP_JWT_LOCATION,
                    MP_JWT_REQUIRE_ISS,
                    TOKEN_HEADER,
                    TOKEN_COOKIE,
                    ALWAYS_CHECK_AUTHORIZATION,
                    TOKEN_KEY_ID,
                    TOKEN_SCHEMES,
                    REQUIRE_NAMED_PRINCIPAL,
                    DEFAULT_SUB_CLAIM,
                    SUB_PATH,
                    DEFAULT_GROUPS_CLAIM,
                    GROUPS_PATH,
                    GROUPS_SEPARATOR,
                    EXP_GRACE_PERIOD_SECS,
                    MAX_TIME_TO_LIVE_SECS,
                    JWKS_REFRESH_INTERVAL,
                    FORCED_JWKS_REFRESH_INTERVAL,
                    WHITELIST_ALGORITHMS,
                    SIGNATURE_ALGORITHM,
                    KEY_FORMAT,
                    EXPECTED_AUDIENCE,
                    REQUIRED_CLAIMS));
        }
    }

    /**
     * Create JWTAuthContextInfoProvider with the public key and issuer
     *
     * @param publicKey the public key value
     * @param issuer the issuer
     * @return a new instance of JWTAuthContextInfoProvider
     */
    public static JWTAuthContextInfoProvider createWithKey(String publicKey, String issuer) {
        return create(publicKey, NONE, issuer);
    }

    /**
     * Create JWTAuthContextInfoProvider with the public key location and issuer
     *
     * @param publicKeyLocation the public key location
     * @param issuer the issuer
     * @return a new instance of JWTAuthContextInfoProvider
     */
    public static JWTAuthContextInfoProvider createWithKeyLocation(String publicKeyLocation, String issuer) {
        return create(NONE, publicKeyLocation, issuer);
    }

    private static JWTAuthContextInfoProvider create(String publicKey, String publicKeyLocation, String issuer) {
        JWTAuthContextInfoProvider provider = new JWTAuthContextInfoProvider();
        provider.mpJwtPublicKey = publicKey;
        provider.mpJwtLocation = publicKeyLocation;
        provider.mpJwtIssuer = issuer;

        provider.mpJwtRequireIss = true;
        provider.tokenHeader = AUTHORIZATION_HEADER;
        provider.tokenCookie = Optional.empty();
        provider.tokenKeyId = Optional.empty();
        provider.tokenSchemes = BEARER_SCHEME;
        provider.requireNamedPrincipal = Boolean.TRUE;
        provider.defaultSubClaim = Optional.empty();
        provider.subPath = Optional.empty();
        provider.defaultGroupsClaim = Optional.empty();
        provider.groupsPath = Optional.empty();
        provider.expGracePeriodSecs = 60;
        provider.maxTimeToLiveSecs = Optional.empty();
        provider.jwksRefreshInterval = 0;
        provider.forcedJwksRefreshInterval = 30;
        provider.signatureAlgorithm = SignatureAlgorithm.RS256;
        provider.keyFormat = KeyFormat.ANY;
        provider.expectedAudience = Optional.empty();
        provider.groupsSeparator = DEFAULT_GROUPS_SEPARATOR;
        provider.requiredClaims = Optional.empty();

        provider.loaded = JWTAuthConfigProperty.getAllPropertyNames();
        return provider;
    }

    // The MP-JWT spec defined configuration properties
    /**
     * @since 1.1
     */
    private String mpJwtPublicKey = NONE;

    /**
     * @since 1.1
     */
    private String mpJwtIssuer = NONE;

    /**
     * @since 1.1
     */
    private String mpJwtLocation = NONE;

    /**
     * Not part of the 1.1 release, but talked about.
     */
    private boolean mpJwtRequireIss = true;

    // SmallRye JWT specific properties
    /**
     * HTTP header which is expected to contain a JWT token, default value is 'Authorization'
     */
    private String tokenHeader = AUTHORIZATION_HEADER;

    /**
     * Cookie name containing a JWT token. This property is ignored unless the "smallrye.jwt.token.header" is set to 'Cookie'
     */
    private Optional<String> tokenCookie;

    /**
     * If `true` then `Authorization` header will be checked even if the `smallrye.jwt.token.header` is set to `Cookie` but no
     * cookie with a `smallrye.jwt.token.cookie` name exists.
     */
    private boolean alwaysCheckAuthorization = false;

    /**
     * The key identifier ('kid'). If it is set then if the token contains 'kid' then both values must match. It will also be
     * used to
     * select a JWK key from a JWK set.
     */
    private Optional<String> tokenKeyId;

    /**
     * The scheme used with an HTTP Authorization header.
     */
    private String tokenSchemes = BEARER_SCHEME;

    /**
     * Check that the JWT has at least one of 'sub', 'upn' or 'preferred_user_name' set. If not the JWT validation will
     * fail.
     */
    private boolean requireNamedPrincipal = false;

    /**
     * Default subject claim value. This property can be used to support the JWT tokens without a 'sub' claim.
     */
    private Optional<String> defaultSubClaim;

    /**
     * Path to the claim containing the sub. It starts from the top level JSON object and
     * can contain multiple segments where each segment represents a JSON object name only, example: "realm/sub".
     * Use double quotes with the namespace qualified claim names.
     * This property can be used if a token has no 'sub' claim but has the sub set in a different claim.
     */
    private Optional<String> subPath;

    /**
     * Default groups claim value. This property can be used to support the JWT tokens without a 'groups' claim.
     */
    private Optional<String> defaultGroupsClaim;

    /**
     * Path to the claim containing an array of groups. It starts from the top level JSON object and
     * can contain multiple segments where each segment represents a JSON object name only, example: "realm/groups".
     * Use double quotes with the namespace qualified claim names.
     * This property can be used if a token has no 'groups' claim but has the groups set in a different claim.
     */
    private Optional<String> groupsPath;

    /**
     * Separator for splitting a string which may contain multiple group values.
     * It will only be used if the "smallrye.jwt.path.groups" property points to a custom claim whose value is a string.
     * The default value is a single space because the standard 'scope' claim may contain a space separated sequence.
     */
    private String groupsSeparator = DEFAULT_GROUPS_SEPARATOR;

    private int expGracePeriodSecs = 60;

    /**
     * The maximum number of seconds that a JWT may be issued for use. Effectively, the difference
     * between the expiration date of the JWT and the issued at date must not exceed this value.
     */
    Optional<Long> maxTimeToLiveSecs;

    /**
     * JWK cache refresh interval in minutes. It will be ignored unless the 'mp.jwt.verify.publickey.location' property points
     * to the HTTPS URL based JWK set.
     * Note this property will only be used if no HTTP Cache-Control response header with a positive 'max-age' parameter value
     * is available.
     */
    private int jwksRefreshInterval = 60;

    /**
     * Forced JWK cache refresh interval in minutes which is used to restrict the frequency of the forced refresh attempts which
     * may happen when the token verification fails due to the cache having no JWK key with a 'kid' property matching the
     * current token's 'kid' header.
     * It will be ignored unless the 'mp.jwt.verify.publickey.location' points to the HTTPS URL based JWK set.
     */
    private int forcedJwksRefreshInterval = 30;

    /**
     * List of supported JSON Web Algorithm RSA and Elliptic Curve signing algorithms, default is RS256.
     */
    @Deprecated
    private Optional<String> whitelistAlgorithms;

    /**
     * Supported JSON Web Algorithm asymmetric signature algorithm (RS256 or ES256), default is RS256.
     */
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;

    /**
     * Supported key format. By default a key can be in any of the supported formats:
     * PEM key, PEM certificate, JWK key set or single JWK (possibly Base64URL-encoded).
     */
    private KeyFormat keyFormat = KeyFormat.ANY;

    /**
     * The audience value(s) that identify valid recipient(s) of a JWT. Audience validation
     * will succeed, if any one of the provided values is equal to any one of the values of
     * the "aud" claim in the JWT. The config value should be specified as a comma-separated
     * list per MP Config requirements for a collection property.
     *
     * @since 2.0.3
     */
    Optional<Set<String>> expectedAudience;

    /**
     * List of claim names that must be present in the JWT for it to be valid. The configuration should be specified
     * as a comma-separated list.
     */
    Optional<Set<String>> requiredClaims;

    @Produces
    Optional<JWTAuthContextInfo> getOptionalContextInfo() {
        // Log the config values
        ConfigLogging.log.configValues(
                getMpJwtPublicKey().orElse("missing"),
                mpJwtIssuer,
                getMpJwtIssuer() != null ? mpJwtIssuer : "missing");
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();

        if (getMpJwtIssuer() != null && !getMpJwtIssuer().equals(NONE)) {
            contextInfo.setIssuedBy(getMpJwtIssuer().trim());
        } else {
            // If there is no expected issuer configured, don't validate it; new in MP-JWT 1.1
            contextInfo.setRequireIssuer(false);
        }

        // Default is to require iss claim
        contextInfo.setRequireIssuer(getMpJwtRequireIss().get());

        // The MP-JWT location can be a PEM, JWK or JWKS
        if (getMpJwtPublicKey().isPresent() && !NONE.equals(mpJwtPublicKey)) {
            contextInfo.setPublicKeyContent(mpJwtPublicKey);
        } else if (getMpJwtLocation().isPresent() && !NONE.equals(mpJwtLocation)) {
            contextInfo.setPublicKeyLocation(mpJwtLocation.trim());
        }
        if (getTokenHeader() != null) {
            contextInfo.setTokenHeader(getTokenHeader());
        }

        contextInfo.setAlwaysCheckAuthorization(isAlwaysCheckAuthorization());

        contextInfo.setTokenKeyId(getTokenKeyId().orElse(null));
        contextInfo.setRequireNamedPrincipal(getRequireNamedPrincipal());
        SmallryeJwtUtils.setContextTokenCookie(contextInfo, getTokenCookie());
        SmallryeJwtUtils.setTokenSchemes(contextInfo, getTokenSchemes());
        contextInfo.setDefaultSubjectClaim(getDefaultSubjectClaim().orElse(null));
        SmallryeJwtUtils.setContextSubPath(contextInfo, getSubjectPath());
        contextInfo.setDefaultGroupsClaim(getDefaultGroupsClaim().orElse(null));
        SmallryeJwtUtils.setContextGroupsPath(contextInfo, getGroupsPath());
        contextInfo.setExpGracePeriodSecs(getExpGracePeriodSecs().get());
        contextInfo.setMaxTimeToLiveSecs(getMaxTimeToLiveSecs().orElse(null));
        contextInfo.setJwksRefreshInterval(getJwksRefreshInterval().get());
        contextInfo.setForcedJwksRefreshInterval(getForcedJwksRefreshInterval());
        if (getSignatureAlgorithm().get() == SignatureAlgorithm.HS256) {
            throw ConfigMessages.msg.hs256NotSupported();
        }
        contextInfo.setSignatureAlgorithm(getSignatureAlgorithm().get());
        contextInfo.setKeyFormat(getKeyFormat());
        contextInfo.setExpectedAudience(getExpectedAudience().orElse(null));
        contextInfo.setGroupsSeparator(getGroupsSeparator());
        contextInfo.setRequiredClaims(getRequiredClaims().orElse(null));

        return Optional.of(contextInfo);
    }

    @SuppressWarnings("deprecation")
    protected void decodeMpJwtPublicKey(JWTAuthContextInfo contextInfo) {
        if (mpJwtPublicKey != null || NONE.equals(mpJwtPublicKey)) {
            return;
        }

        // Need to decode what this is...
        try {
            RSAPublicKey pk = (RSAPublicKey) KeyUtils.decodeJWKSPublicKey(mpJwtPublicKey);
            contextInfo.setSignerKey(pk);
            ConfigLogging.log.publicKeyParsedAsJwk();
        } catch (Exception e) {
            // Try as PEM key value
            ConfigLogging.log.parsingPublicKeyAsJwkFailed(e.getMessage());
            try {
                RSAPublicKey pk = (RSAPublicKey) KeyUtils.decodePublicKey(mpJwtPublicKey);
                contextInfo.setSignerKey(pk);
                ConfigLogging.log.publicKeyParsedAsPem();
            } catch (Exception e1) {
                throw ConfigMessages.msg.parsingPublicKeyFailed(e1);
            }
        }

    }

    public Optional<String> getMpJwtPublicKey() {
        if (!loaded.contains(JWTAuthConfigProperty.MP_JWT_PUBLIC_KEY)) {
            mpJwtPublicKey = config.getValue(JWTAuthConfigProperty.MP_JWT_PUBLIC_KEY, String.class);
            loaded.add(JWTAuthConfigProperty.MP_JWT_PUBLIC_KEY);
        }
        return Optional.ofNullable(mpJwtPublicKey);
    }

    public String getMpJwtIssuer() {
        if (!loaded.contains(JWTAuthConfigProperty.MP_JWT_ISSUER)) {
            mpJwtIssuer = config.getValue(JWTAuthConfigProperty.MP_JWT_ISSUER, String.class);
            loaded.add(JWTAuthConfigProperty.MP_JWT_ISSUER);
        }
        return mpJwtIssuer;
    }

    public Optional<String> getMpJwtLocation() {
        if (!loaded.contains(JWTAuthConfigProperty.MP_JWT_LOCATION)) {
            mpJwtLocation = config.getValue(JWTAuthConfigProperty.MP_JWT_LOCATION, String.class);
            loaded.add(JWTAuthConfigProperty.MP_JWT_LOCATION);
        }
        return Optional.ofNullable(mpJwtLocation);
    }

    public Optional<Boolean> getMpJwtRequireIss() {
        if (!loaded.contains(JWTAuthConfigProperty.MP_JWT_REQUIRE_ISS)) {
            mpJwtRequireIss = config.getValue(JWTAuthConfigProperty.MP_JWT_REQUIRE_ISS, Boolean.class);
            loaded.add(JWTAuthConfigProperty.MP_JWT_REQUIRE_ISS);
        }
        return Optional.ofNullable(mpJwtRequireIss);
    }

    public String getTokenHeader() {
        if (!loaded.contains(JWTAuthConfigProperty.TOKEN_HEADER)) {
            tokenHeader = config.getValue(JWTAuthConfigProperty.TOKEN_HEADER, String.class);
            loaded.add(JWTAuthConfigProperty.TOKEN_HEADER);
        }
        return tokenHeader;
    }

    public Optional<String> getTokenCookie() {
        if (!loaded.contains(JWTAuthConfigProperty.TOKEN_COOKIE)) {
            tokenCookie = config.getOptionalValue(JWTAuthConfigProperty.TOKEN_COOKIE, String.class);
            loaded.add(JWTAuthConfigProperty.TOKEN_COOKIE);
        }
        return tokenCookie;
    }

    public boolean isAlwaysCheckAuthorization() {
        if (!loaded.contains(JWTAuthConfigProperty.ALWAYS_CHECK_AUTHORIZATION)) {
            alwaysCheckAuthorization = config.getValue(JWTAuthConfigProperty.ALWAYS_CHECK_AUTHORIZATION, Boolean.class);
            loaded.add(JWTAuthConfigProperty.ALWAYS_CHECK_AUTHORIZATION);
        }
        return alwaysCheckAuthorization;
    }

    public Optional<String> getTokenKeyId() {
        if (!loaded.contains(JWTAuthConfigProperty.ALWAYS_CHECK_AUTHORIZATION)) {
            tokenKeyId = config.getOptionalValue(JWTAuthConfigProperty.TOKEN_KEY_ID, String.class);
            loaded.add(JWTAuthConfigProperty.ALWAYS_CHECK_AUTHORIZATION);
        }
        return tokenKeyId;
    }

    public Optional<String> getTokenSchemes() {
        if (!loaded.contains(JWTAuthConfigProperty.TOKEN_SCHEMES)) {
            tokenSchemes = config.getValue(JWTAuthConfigProperty.TOKEN_SCHEMES, String.class);
            loaded.add(JWTAuthConfigProperty.TOKEN_SCHEMES);
        }
        return Optional.ofNullable(tokenSchemes);
    }

    public boolean getRequireNamedPrincipal() {
        if (!loaded.contains(JWTAuthConfigProperty.REQUIRE_NAMED_PRINCIPAL)) {
            requireNamedPrincipal = config.getValue(JWTAuthConfigProperty.REQUIRE_NAMED_PRINCIPAL, Boolean.class);
            loaded.add(JWTAuthConfigProperty.REQUIRE_NAMED_PRINCIPAL);
        }
        return requireNamedPrincipal;
    }

    public Optional<Integer> getExpGracePeriodSecs() {
        if (!loaded.contains(JWTAuthConfigProperty.EXP_GRACE_PERIOD_SECS)) {
            expGracePeriodSecs = config.getValue(JWTAuthConfigProperty.EXP_GRACE_PERIOD_SECS, Integer.class);
            loaded.add(JWTAuthConfigProperty.EXP_GRACE_PERIOD_SECS);
        }
        return Optional.of(expGracePeriodSecs);
    }

    public Optional<Long> getMaxTimeToLiveSecs() {
        if (!loaded.contains(JWTAuthConfigProperty.MAX_TIME_TO_LIVE_SECS)) {
            maxTimeToLiveSecs = config.getOptionalValue(JWTAuthConfigProperty.MAX_TIME_TO_LIVE_SECS, Long.class);
            loaded.add(JWTAuthConfigProperty.MAX_TIME_TO_LIVE_SECS);
        }
        return maxTimeToLiveSecs;
    }

    public Optional<Integer> getJwksRefreshInterval() {
        if (!loaded.contains(JWTAuthConfigProperty.JWKS_REFRESH_INTERVAL)) {
            jwksRefreshInterval = config.getValue(JWTAuthConfigProperty.JWKS_REFRESH_INTERVAL, Integer.class);
            loaded.add(JWTAuthConfigProperty.JWKS_REFRESH_INTERVAL);
        }
        return Optional.of(jwksRefreshInterval);
    }

    public int getForcedJwksRefreshInterval() {
        if (!loaded.contains(JWTAuthConfigProperty.FORCED_JWKS_REFRESH_INTERVAL)) {
            forcedJwksRefreshInterval = config.getValue(JWTAuthConfigProperty.FORCED_JWKS_REFRESH_INTERVAL, Integer.class);
            loaded.add(JWTAuthConfigProperty.FORCED_JWKS_REFRESH_INTERVAL);
        }
        return forcedJwksRefreshInterval;
    }

    public Optional<String> getDefaultGroupsClaim() {
        if (!loaded.contains(JWTAuthConfigProperty.DEFAULT_GROUPS_CLAIM)) {
            defaultGroupsClaim = config.getOptionalValue(JWTAuthConfigProperty.DEFAULT_GROUPS_CLAIM, String.class);
            loaded.add(JWTAuthConfigProperty.DEFAULT_GROUPS_CLAIM);
        }
        return defaultGroupsClaim;
    }

    public Optional<String> getGroupsPath() {
        if (!loaded.contains(JWTAuthConfigProperty.GROUPS_PATH)) {
            groupsPath = config.getOptionalValue(JWTAuthConfigProperty.GROUPS_PATH, String.class);
            loaded.add(JWTAuthConfigProperty.GROUPS_PATH);
        }
        return groupsPath;
    }

    public String getGroupsSeparator() {
        if (!loaded.contains(JWTAuthConfigProperty.GROUPS_SEPARATOR)) {
            groupsSeparator = config.getValue(JWTAuthConfigProperty.GROUPS_SEPARATOR, String.class);
            loaded.add(JWTAuthConfigProperty.GROUPS_SEPARATOR);
        }
        return groupsSeparator;
    }

    public Optional<String> getSubjectPath() {
        if (!loaded.contains(JWTAuthConfigProperty.SUB_PATH)) {
            subPath = config.getOptionalValue(JWTAuthConfigProperty.SUB_PATH, String.class);
            loaded.add(JWTAuthConfigProperty.SUB_PATH);
        }
        return subPath;
    }

    public Optional<String> getDefaultSubjectClaim() {
        if (!loaded.contains(JWTAuthConfigProperty.DEFAULT_SUB_CLAIM)) {
            defaultSubClaim = config.getOptionalValue(JWTAuthConfigProperty.DEFAULT_SUB_CLAIM, String.class);
            loaded.add(JWTAuthConfigProperty.DEFAULT_SUB_CLAIM);
        }
        return defaultSubClaim;
    }

    @Deprecated
    public Optional<String> getWhitelistAlgorithms() {
        if (!loaded.contains(JWTAuthConfigProperty.WHITELIST_ALGORITHMS)) {
            whitelistAlgorithms = config.getOptionalValue(JWTAuthConfigProperty.WHITELIST_ALGORITHMS, String.class);
            loaded.add(JWTAuthConfigProperty.WHITELIST_ALGORITHMS);
        }
        return whitelistAlgorithms;
    }

    public Optional<SignatureAlgorithm> getSignatureAlgorithm() {
        if (!loaded.contains(JWTAuthConfigProperty.SIGNATURE_ALGORITHM)) {
            signatureAlgorithm = config.getValue(JWTAuthConfigProperty.SIGNATURE_ALGORITHM, SignatureAlgorithm.class);
            loaded.add(JWTAuthConfigProperty.SIGNATURE_ALGORITHM);
        }
        return Optional.of(signatureAlgorithm);
    }

    public KeyFormat getKeyFormat() {
        if (!loaded.contains(JWTAuthConfigProperty.KEY_FORMAT)) {
            keyFormat = config.getValue(JWTAuthConfigProperty.KEY_FORMAT, KeyFormat.class);
            loaded.add(JWTAuthConfigProperty.KEY_FORMAT);
        }
        return keyFormat;
    }

    public Optional<Set<String>> getExpectedAudience() {
        if (!loaded.contains(JWTAuthConfigProperty.EXPECTED_AUDIENCE)) {
            Optional<String> aux = config.getOptionalValue(JWTAuthConfigProperty.EXPECTED_AUDIENCE, String.class);
            if (aux.isPresent()) {
                expectedAudience = Optional.of(new HashSet(Arrays.asList(aux.get().split(","))));
            }
            loaded.add(JWTAuthConfigProperty.EXPECTED_AUDIENCE);
        }
        return expectedAudience;
    }

    public Optional<Set<String>> getRequiredClaims() {
        if (!loaded.contains(JWTAuthConfigProperty.REQUIRED_CLAIMS)) {
            Optional<String> aux = config.getOptionalValue(JWTAuthConfigProperty.REQUIRED_CLAIMS, String.class);
            if (aux.isPresent()) {
                requiredClaims = Optional.of(new HashSet(Arrays.asList(aux.get().split(","))));
            }
            loaded.add(JWTAuthConfigProperty.REQUIRED_CLAIMS);
        }
        return requiredClaims;
    }

    @Produces
    @ApplicationScoped
    public JWTAuthContextInfo getContextInfo() {
        return getOptionalContextInfo().get();
    }
}
