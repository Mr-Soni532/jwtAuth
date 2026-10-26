package com.demo.jwtauth.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;

/**
 * STEP: Clean JSON errors instead of Spring's default HTML/blank responses.
 *
 *  401 Unauthorized -> "Who are you?"  (no token / invalid / expired token)
 *  403 Forbidden    -> "I know who you are, but you are not allowed" (wrong role)
 */
public final class SecurityErrorHandlers {

    private SecurityErrorHandlers() {}

    private static void write(HttpServletResponse response, int status, String error,
                              String message, String path) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(String.format(
                "{\"timestamp\":\"%s\",\"status\":%d,\"error\":\"%s\",\"message\":\"%s\",\"path\":\"%s\"}",
                Instant.now(), status, error, message, path));
    }

    @Component
    public static class JwtAuthEntryPoint implements AuthenticationEntryPoint {
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response,
                             AuthenticationException ex) throws IOException {
            Object jwtError = request.getAttribute("jwt_error");
            String message = jwtError != null ? jwtError.toString() : "Authentication required";
            write(response, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", message, request.getRequestURI());
        }
    }

    @Component
    public static class JwtAccessDeniedHandler implements AccessDeniedHandler {
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response,
                           AccessDeniedException ex) throws IOException {
            write(response, HttpServletResponse.SC_FORBIDDEN, "Forbidden",
                    "You do not have permission to access this resource", request.getRequestURI());
        }
    }
}
