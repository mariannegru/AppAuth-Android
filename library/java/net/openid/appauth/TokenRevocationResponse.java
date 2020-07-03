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

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import static net.openid.appauth.AdditionalParamsProcessor.checkAdditionalParams;
import static net.openid.appauth.AdditionalParamsProcessor.extractAdditionalParams;
import static net.openid.appauth.Preconditions.checkNotEmpty;
import static net.openid.appauth.Preconditions.checkNotNull;

/**
 * A response to a token revocation request.
 *
 * @see TokenRevocationRequest
 * @see "The OAuth 2.0 Token Revocation (RFC 7009), Section 2.2
 * <https://tools.ietf.org/html/rfc7009#section-2.2>"
 */
public class TokenRevocationResponse {

    /**
     * Indicates that a provided access token is a bearer token.
     *
     * @see "The OAuth 2.0 Authorization Framework (RFC 6749), Section 7.1
     * <https://tools.ietf.org/html/rfc6749#section-7.1>"
     */
    public static final String TOKEN_TYPE_BEARER = "Bearer";

    @VisibleForTesting
    static final String KEY_REQUEST = "request";

    @VisibleForTesting
    static final String KEY_TOKEN = "token";

    @VisibleForTesting
    static final String KEY_ADDITIONAL_PARAMETERS = "additionalParameters";

    private static final Set<String> BUILT_IN_PARAMS = new HashSet<>(Arrays.asList(
            KEY_TOKEN
    ));

    /**
     * The token request associated with this response.
     */
    @NonNull
    public final TokenRevocationRequest request;

    /**
     * Additional, non-standard parameters in the response.
     */
    @NonNull
    public final Map<String, String> additionalParameters;

    /**
     * Creates instances of {@link TokenRevocationResponse}.
     */
    public static final class Builder {
        @NonNull
        private TokenRevocationRequest mRequest;

        @NonNull
        private Map<String, String> mAdditionalParameters;

        /**
         * Creates a token response associated with the specified request.
         */
        public Builder(@NonNull TokenRevocationRequest request) {
            setRequest(request);
            mAdditionalParameters = Collections.emptyMap();
        }

        /**
         * Extracts token response fields from a JSON string.
         *
         * @throws JSONException if the JSON is malformed or has incorrect value types for fields.
         */
        @NonNull
        public Builder fromResponseJsonString(@NonNull String jsonStr) throws JSONException {
            checkNotEmpty(jsonStr, "json cannot be null or empty");
            return fromResponseJson(new JSONObject(jsonStr));
        }

        /**
         * Extracts token response fields from a JSON object.
         *
         * @throws JSONException if the JSON is malformed or has incorrect value types for fields.
         */
        @NonNull
        public Builder fromResponseJson(@NonNull JSONObject json) throws JSONException {
            setAdditionalParameters(extractAdditionalParams(json, BUILT_IN_PARAMS));

            return this;
        }

        /**
         * Specifies the request associated with this response. Must not be null.
         */
        @NonNull
        public Builder setRequest(@NonNull TokenRevocationRequest request) {
            mRequest = checkNotNull(request, "request cannot be null");
            return this;
        }

        /**
         * Specifies the additional, non-standard parameters received as part of the response.
         */
        @NonNull
        public Builder setAdditionalParameters(@Nullable Map<String, String> additionalParameters) {
            mAdditionalParameters = checkAdditionalParams(additionalParameters, BUILT_IN_PARAMS);
            return this;
        }

        /**
         * Creates the token response instance.
         */
        public TokenRevocationResponse build() {
            return new TokenRevocationResponse(
                    mRequest,
                    mAdditionalParameters);
        }
    }

    TokenRevocationResponse(
            @NonNull TokenRevocationRequest request,
            @NonNull Map<String, String> additionalParameters) {
        this.request = request;
        this.additionalParameters = additionalParameters;
    }

    /**
     * Produces a JSON string representation of the token response for persistent storage or
     * local transmission (e.g. between activities).
     */
    public JSONObject jsonSerialize() {
        JSONObject json = new JSONObject();
        JsonUtil.put(json, KEY_REQUEST, request.jsonSerialize());
        JsonUtil.put(json, KEY_ADDITIONAL_PARAMETERS,
                JsonUtil.mapToJsonObject(additionalParameters));
        return json;
    }

    /**
     * Produces a JSON string representation of the token response for persistent storage or
     * local transmission (e.g. between activities). This method is just a convenience wrapper
     * for {@link #jsonSerialize()}, converting the JSON object to its string form.
     */
    public String jsonSerializeString() {
        return jsonSerialize().toString();
    }

    /**
     * Reads a token response from a JSON string, and associates it with the provided request.
     * If a request is not provided, its serialized form is expected to be found in the JSON
     * (as if produced by a prior call to {@link #jsonSerialize()}.
     * @throws JSONException if the JSON is malformed or missing required fields.
     */
    @NonNull
    public static TokenRevocationResponse jsonDeserialize(@NonNull JSONObject json) throws JSONException {
        if (!json.has(KEY_REQUEST)) {
            throw new IllegalArgumentException(
                    "token request not provided and not found in JSON");
        }
        return new TokenRevocationResponse.Builder(
                TokenRevocationRequest.jsonDeserialize(json.getJSONObject(KEY_REQUEST)))
                .setAdditionalParameters(JsonUtil.getStringMap(json, KEY_ADDITIONAL_PARAMETERS))
                .build();
    }

    /**
     * Reads a token response from a JSON string, and associates it with the provided request.
     * If a request is not provided, its serialized form is expected to be found in the JSON
     * (as if produced by a prior call to {@link #jsonSerialize()}.
     * @throws JSONException if the JSON is malformed or missing required fields.
     */
    @NonNull
    public static TokenRevocationResponse jsonDeserialize(@NonNull String jsonStr) throws JSONException {
        checkNotEmpty(jsonStr, "jsonStr cannot be null or empty");
        return jsonDeserialize(new JSONObject(jsonStr));
    }
}
