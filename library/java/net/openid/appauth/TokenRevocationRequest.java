/*
 * Copyright 2015 The AppAuth for Android Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openid.appauth;

import android.net.Uri;
import android.text.TextUtils;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import static net.openid.appauth.AdditionalParamsProcessor.checkAdditionalParams;
import static net.openid.appauth.Preconditions.checkNotEmpty;
import static net.openid.appauth.Preconditions.checkNotNull;
import static net.openid.appauth.Preconditions.checkNullOrNotEmpty;

/**
 * An OAuth2 token revocation request. These are used to revocation tokens.
 *
 * @see "The OAuth 2.0 Token Revocation (RFC 7009), Section 2.1
 * <https://tools.ietf.org/html/rfc7009#section-2.1>"
 */
public class TokenRevocationRequest {

    @VisibleForTesting
    static final String KEY_CONFIGURATION = "configuration";
    @VisibleForTesting
    static final String KEY_CLIENT_ID = "clientId";
    @VisibleForTesting
    static final String KEY_REDIRECT_URI = "redirectUri";
    @VisibleForTesting
    static final String KEY_TOKEN = "token";
    @VisibleForTesting
    static final String KEY_ADDITIONAL_PARAMETERS = "additionalParameters";

    public static final String PARAM_CLIENT_ID = "client_id";

    @VisibleForTesting
    static final String PARAM_REDIRECT_URI = "redirect_uri";

    @VisibleForTesting
    static final String PARAM_CODE_VERIFIER = "code_verifier";

    @VisibleForTesting
    static final String PARAM_TOKEN = "token";

    private static final Set<String> BUILT_IN_PARAMS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    PARAM_CLIENT_ID,
                    PARAM_REDIRECT_URI,
                    PARAM_TOKEN)));

    /**
     * The service's {@link AuthorizationServiceConfiguration configuration}.
     * This configuration specifies how to connect to a particular OAuth provider.
     * Configurations may be
     * {@link
     * AuthorizationServiceConfiguration#AuthorizationServiceConfiguration(Uri, Uri, Uri, Uri)
     * created manually}, or
     * {@link AuthorizationServiceConfiguration#fetchFromUrl(Uri,
     * AuthorizationServiceConfiguration.RetrieveConfigurationCallback)
     * via an OpenID Connect Discovery Document}.
     */
    @NonNull
    public final AuthorizationServiceConfiguration configuration;

    /**
     * The client identifier.
     *
     * @see "The OAuth 2.0 Authorization Framework (RFC 6749), Section 4
     * <https://tools.ietf.org/html/rfc6749#section-4>"
     * @see "The OAuth 2.0 Authorization Framework (RFC 6749), Section 4.1.1
     * <https://tools.ietf.org/html/rfc6749#section-4.1.1>"
     */
    @NonNull
    public final String clientId;

    /**
     * The client's redirect URI. Required if this token request is to exchange an authorization
     * code for one or more tokens, and must be identical to the value specified in the original
     * authorization request.
     *
     * @see "The OAuth 2.0 Authorization Framework (RFC 6749), Section 3.1.2
     * <https://tools.ietf.org/html/rfc6749#section-3.1.2>"
     * @see "The OAuth 2.0 Authorization Framework (RFC 6749), Section 4.1.3
     * <https://tools.ietf.org/html/rfc6749#section-4.1.3>"
     */
    @Nullable
    public final Uri redirectUri;

    /**
     * A token to be revoked.
     *
     * @see "The OAuth 2.0 Token Revocation (RFC 7009), Section 2.1
     * <https://tools.ietf.org/html/rfc7009#section-2.1>"
     */
    @Nullable
    public final String token;

    /**
     * The code verifier that was used to generate the challenge in the original authorization
     * request, if one was used.
     *
     * @see "Proof Key for Code Exchange by OAuth Public Clients (RFC 7636), Section 4
     * <https://tools.ietf.org/html/rfc7636#section-4>"
     */
    @Nullable
    public final String codeVerifier;

    /**
     * Additional parameters to be passed as part of the request.
     */
    @NonNull
    public final Map<String, String> additionalParameters;

    /**
     * Creates instances of {@link TokenRevocationRequest}.
     */
    public static final class Builder {

        @NonNull
        private AuthorizationServiceConfiguration mConfiguration;

        @NonNull
        private String mClientId;

        @Nullable
        private Uri mRedirectUri;

        @Nullable
        private String mToken;

        @Nullable
        private String mCodeVerifier;

        @NonNull
        private Map<String, String> mAdditionalParameters;

        /**
         * Creates a token request builder with the specified mandatory properties.
         */
        public Builder(
                @NonNull AuthorizationServiceConfiguration configuration,
                @NonNull String clientId) {
            setConfiguration(configuration);
            setClientId(clientId);
            mAdditionalParameters = new LinkedHashMap<>();
        }

        /**
         * Specifies the authorization service configuration for the request, which must not
         * be null or empty.
         */
        @NonNull
        public Builder setConfiguration(@NonNull AuthorizationServiceConfiguration configuration) {
            mConfiguration = checkNotNull(configuration);
            return this;
        }

        /**
         * Specifies the client ID for the token request, which must not be null or empty.
         */
        @NonNull
        public Builder setClientId(@NonNull String clientId) {
            mClientId = checkNotEmpty(clientId, "clientId cannot be null or empty");
            return this;
        }

        /**
         * Specifies the redirect URI for the request. This is required for authorization code
         * exchanges, but otherwise optional. If specified, the redirect URI must have a scheme.
         */
        @NonNull
        public Builder setRedirectUri(@Nullable Uri redirectUri) {
            if (redirectUri != null) {
                checkNotNull(redirectUri.getScheme(), "redirectUri must have a scheme");
            }
            mRedirectUri = redirectUri;
            return this;
        }

        /**
         * Specifies the refresh token for the request. If a non-null value is provided, it must
         * not be empty.
         *
         * Specifying a refresh token normally implies that this is a request to exchange the
         * refresh token for a new token. If this is not intended, the grant type should be
         * explicit set.
         */
        @NonNull
        public Builder setToken(@Nullable String token) {
            if (token != null) {
                checkNotEmpty(token, "token cannot be empty if defined");
            }
            mToken = token;
            return this;
        }

        /**
         * Specifies the code verifier for an authorization code exchange request. This must match
         * the code verifier that was used to generate the challenge sent in the request that
         * produced the authorization code.
         */
        public Builder setCodeVerifier(@Nullable String codeVerifier) {
            if (codeVerifier != null) {
                CodeVerifierUtil.checkCodeVerifier(codeVerifier);
            }

            mCodeVerifier = codeVerifier;
            return this;
        }

        /**
         * Specifies an additional set of parameters to be sent as part of the request.
         */
        @NonNull
        public Builder setAdditionalParameters(@Nullable Map<String, String> additionalParameters) {
            mAdditionalParameters = checkAdditionalParams(additionalParameters, BUILT_IN_PARAMS);
            return this;
        }

        /**
         * Produces a {@link TokenRevocationRequest} instance, if all necessary values have been provided.
         */
        @NonNull
        public TokenRevocationRequest build() {
            return new TokenRevocationRequest(
                    mConfiguration,
                    mClientId,
                    mRedirectUri,
                    mToken,
                    mCodeVerifier,
                    Collections.unmodifiableMap(mAdditionalParameters));
        }
    }

    private TokenRevocationRequest(
            @NonNull AuthorizationServiceConfiguration configuration,
            @NonNull String clientId,
            @Nullable Uri redirectUri,
            @Nullable String token,
            @Nullable String codeVerifier,
            @NonNull Map<String, String> additionalParameters) {
        this.configuration = configuration;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.token = token;
        this.codeVerifier = codeVerifier;
        this.additionalParameters = additionalParameters;
    }

    /**
     * Produces the set of request parameters for this query, which can be further
     * processed into a request body.
     */
    @NonNull
    public Map<String, String> getRequestParameters() {
        Map<String, String> params = new HashMap<>();
        putIfNotNull(params, PARAM_REDIRECT_URI, redirectUri);
        putIfNotNull(params, PARAM_TOKEN, token);
        putIfNotNull(params, PARAM_CODE_VERIFIER, codeVerifier);

        for (Entry<String, String> param : additionalParameters.entrySet()) {
            params.put(param.getKey(), param.getValue());
        }

        return params;
    }

    private void putIfNotNull(Map<String, String> map, String key, Object value) {
        if (value != null) {
            map.put(key, value.toString());
        }
    }

    /**
     * Produces a JSON string representation of the token request for persistent storage or
     * local transmission (e.g. between activities).
     */
    @NonNull
    public JSONObject jsonSerialize() {
        JSONObject json = new JSONObject();
        JsonUtil.put(json, KEY_CONFIGURATION, configuration.toJson());
        JsonUtil.put(json, KEY_CLIENT_ID, clientId);
        JsonUtil.putIfNotNull(json, KEY_REDIRECT_URI, redirectUri);
        JsonUtil.putIfNotNull(json, KEY_TOKEN, token);
        JsonUtil.put(json, KEY_ADDITIONAL_PARAMETERS,
                JsonUtil.mapToJsonObject(additionalParameters));
        return json;
    }

    /**
     * Produces a JSON string representation of the token request for persistent storage or
     * local transmission (e.g. between activities). This method is just a convenience wrapper
     * for {@link #jsonSerialize()}, converting the JSON object to its string form.
     */
    @NonNull
    public String jsonSerializeString() {
        return jsonSerialize().toString();
    }

    /**
     * Reads a token request from a JSON string representation produced by
     * {@link #jsonSerialize()}.
     * @throws JSONException if the provided JSON does not match the expected structure.
     */
    @NonNull
    public static TokenRevocationRequest jsonDeserialize(JSONObject json) throws JSONException {
        checkNotNull(json, "json object cannot be null");

        TokenRevocationRequest.Builder builder = new TokenRevocationRequest.Builder(
                AuthorizationServiceConfiguration.fromJson(json.getJSONObject(KEY_CONFIGURATION)),
                JsonUtil.getString(json, KEY_CLIENT_ID))
                .setRedirectUri(JsonUtil.getUriIfDefined(json, KEY_REDIRECT_URI))
                .setToken(JsonUtil.getStringIfDefined(json, KEY_TOKEN))
                .setAdditionalParameters(JsonUtil.getStringMap(json, KEY_ADDITIONAL_PARAMETERS));

        return builder.build();
    }

    /**
     * Reads a token request from a JSON string representation produced by
     * {@link #jsonSerializeString()}. This method is just a convenience wrapper for
     * {@link #jsonDeserialize(JSONObject)}, converting the JSON string to its JSON object form.
     * @throws JSONException if the provided JSON does not match the expected structure.
     */
    @NonNull
    public static TokenRevocationRequest jsonDeserialize(@NonNull String json) throws JSONException {
        checkNotNull(json, "json string cannot be null");
        return jsonDeserialize(new JSONObject(json));
    }
}
