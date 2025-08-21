package com.base.service;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * @author YISivlay
 */
public class CustomAccessTokenResponseHandler implements AuthenticationSuccessHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        if (authentication instanceof OAuth2AccessTokenAuthenticationToken accessTokenAuthentication) {
            try {
                OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();
                OAuth2RefreshToken refreshToken = accessTokenAuthentication.getRefreshToken();

                Map<String, Object> tokenResponse = new LinkedHashMap<>();
                tokenResponse.put("access_token", accessToken.getTokenValue());
                tokenResponse.put("token_type", accessToken.getTokenType().getValue());
                tokenResponse.put("expires_in", Objects.requireNonNull(accessToken.getExpiresAt()).getEpochSecond() - Instant.now().getEpochSecond());

                if (refreshToken != null) {
                    tokenResponse.put("refresh_token", refreshToken.getTokenValue());
                }

                // Add additional token metadata
                tokenResponse.put("scope", accessToken.getScopes().stream().collect(Collectors.joining(" ")));

                // Add custom claims if available
                if (accessTokenAuthentication.getAdditionalParameters() != null) {
                    tokenResponse.putAll(accessTokenAuthentication.getAdditionalParameters());
                }

                response.setStatus(HttpStatus.OK.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());

                objectMapper.writeValue(response.getWriter(), tokenResponse);

            } catch (Exception e) {
                handleException(response, "token_serialization_error",
                        "Failed to serialize token response: " + e.getMessage(),
                        HttpStatus.INTERNAL_SERVER_ERROR
                );
            }
        } else {
            handleException(response, "invalid_authentication_type",
                    "Unexpected authentication type: " + (authentication != null ? authentication.getClass().getName() : "null"),
                    HttpStatus.INTERNAL_SERVER_ERROR
            );
        }
    }

    private void handleException(HttpServletResponse response, String errorCode, String errorDescription, HttpStatus status) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        Map<String, Object> errorResponse = new LinkedHashMap<>();
        errorResponse.put("error", errorCode);
        errorResponse.put("error_description", errorDescription);
        errorResponse.put("timestamp", Instant.now().toString());

        objectMapper.writeValue(response.getWriter(), errorResponse);
    }
}
