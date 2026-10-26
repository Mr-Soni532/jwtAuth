package com.demo.jwtauth.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * STEP: The heart of JWT auth. Runs ONCE for EVERY request (before Spring's
 * UsernamePasswordAuthenticationFilter).
 *
 * Flow:
 *  1. Read "Authorization: Bearer <token>" header. No header -> continue chain (request stays anonymous;
 *     if the endpoint is protected, Spring returns 401 via our AuthEntryPoint).
 *  2. Extract email from token (this also verifies signature + expiry).
 *  3. Load user from DB, validate token belongs to them and is an ACCESS token.
 *  4. Put an Authentication object into SecurityContextHolder -> now Spring treats
 *     this request as logged-in, and @PreAuthorize / hasRole() work.
 *
 * Because we're STATELESS, this happens on every request; nothing is stored in a session.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // 1. No token -> let it pass; security rules decide if endpoint is public
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        try {
            // 2. Extract username (throws if signature invalid / expired)
            String email = jwtService.extractUsername(token);

            // Only authenticate if not already authenticated for this request
            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // 3. Load user + validate
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                if (jwtService.isTokenValid(token, userDetails, JwtService.TOKEN_TYPE_ACCESS)) {
                    // 4. Mark request as authenticated
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (ExpiredJwtException e) {
            // Store reason so the entry point can send a clear message
            request.setAttribute("jwt_error", "Token expired");
        } catch (JwtException | IllegalArgumentException | UsernameNotFoundException e) {
            request.setAttribute("jwt_error", "Invalid token");
        }

        filterChain.doFilter(request, response);
    }
}
