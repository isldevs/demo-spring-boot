package com.base.service;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author YISivlay
 */
@Component
public class CustomErrorResponseHandler implements AuthenticationFailureHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        try {
            OAuth2Error error = resolveOAuth2Error(exception);
            HttpStatus status = determineHttpStatus(error);

            response.setStatus(status.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());

            Map<String, Object> errorResponse = buildErrorResponse(error, request);
            objectMapper.writeValue(response.getWriter(), errorResponse);

        } catch (Exception e) {
            // Fallback error handling
            handleFallbackError(response);
        }
    }

    private OAuth2Error resolveOAuth2Error(AuthenticationException exception) {
        if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
            return oauth2Exception.getError();
        }

        // Handle specific OAuth2 error scenarios
        if (exception.getCause() instanceof OAuth2AuthenticationException oauth2Exception) {
            return oauth2Exception.getError();
        }

        // Map Spring Security exceptions to OAuth2 errors
        if (exception instanceof BadCredentialsException) {
            return new OAuth2Error("invalid_client", "Invalid client credentials", null);
        } else if (exception instanceof InsufficientAuthenticationException) {
            return new OAuth2Error("invalid_request", "Authentication required", null);
        } else if (exception instanceof AuthenticationServiceException) {
            return new OAuth2Error("server_error", "Authentication service error", null);
        } else if (exception instanceof InternalAuthenticationServiceException) {
            return new OAuth2Error("server_error", "Internal authentication service error", null);
        }

        // Generic error for unhandled exceptions
        return new OAuth2Error("invalid_request", exception.getMessage() != null ? exception.getMessage() : "Authentication failed", null);
    }

    private HttpStatus determineHttpStatus(OAuth2Error error) {
        return switch (error.getErrorCode()) {
            case "invalid_client", "unauthorized_client" -> HttpStatus.UNAUTHORIZED;
            case "access_denied" -> HttpStatus.FORBIDDEN;
            case "server_error" -> HttpStatus.INTERNAL_SERVER_ERROR;
            case "temporarily_unavailable" -> HttpStatus.SERVICE_UNAVAILABLE;
            default -> HttpStatus.BAD_REQUEST;
        };
    }

    private Map<String, Object> buildErrorResponse(OAuth2Error error, HttpServletRequest request) {
        Map<String, Object> errorResponse = new LinkedHashMap<>();
        errorResponse.put("error", error.getErrorCode());

        // Only include description if it exists
        if (error.getDescription() != null) {
            errorResponse.put("error_description", error.getDescription());
        }

        // Add standard metadata
        errorResponse.put("timestamp", Instant.now().toString());
        errorResponse.put("path", request.getRequestURI());

        // Add error URI if available
        if (error.getUri() != null) {
            errorResponse.put("error_uri", error.getUri());
        }

        return errorResponse;
    }

    private void handleFallbackError(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> fallbackError = new LinkedHashMap<>();
        fallbackError.put("error", "server_error");
        fallbackError.put("error_description", "An unexpected error occurred during authentication");
        fallbackError.put("timestamp", Instant.now().toString());

        objectMapper.writeValue(response.getWriter(), fallbackError);
    }
}
