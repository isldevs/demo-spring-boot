package com.base.service;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author YISivlay
 */
public class CustomAuthorizationErrorResponseHandler implements AuthenticationFailureHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        String redirectUri = request.getParameter("redirect_uri");
        String state = request.getParameter("state");

        OAuth2Error error = resolveOAuth2Error(exception);

        if (redirectUri != null) {
            // Redirect back to client with error parameters
            UriComponentsBuilder redirectBuilder = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam("error", error.getErrorCode())
                    .queryParam("error_description", error.getDescription());

            if (state != null) {
                redirectBuilder.queryParam("state", state);
            }

            response.sendRedirect(redirectBuilder.build().toUriString());
        } else {
            // JSON response for API clients
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            Map<String, Object> errorResponse = new LinkedHashMap<>();
            errorResponse.put("error", error.getErrorCode());
            errorResponse.put("error_description", error.getDescription());
            errorResponse.put("timestamp", Instant.now().toString());

            objectMapper.writeValue(response.getWriter(), errorResponse);
        }
    }

    private OAuth2Error resolveOAuth2Error(AuthenticationException exception) {
        // Similar implementation as in CustomErrorResponseHandler
        if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
            return oauth2Exception.getError();
        }
        return new OAuth2Error("server_error", "An unexpected error occurred", null);
    }
}
