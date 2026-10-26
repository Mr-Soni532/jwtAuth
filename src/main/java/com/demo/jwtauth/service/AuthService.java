package com.demo.jwtauth.service;

import com.demo.jwtauth.dto.AuthDtos.*;
import com.demo.jwtauth.entity.Role;
import com.demo.jwtauth.entity.User;
import com.demo.jwtauth.exception.ApiException;
import com.demo.jwtauth.repository.UserRepository;
import com.demo.jwtauth.security.JwtService;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * STEP: Business logic for register / login / refresh.
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager,
                       UserDetailsService userDetailsService,
                       JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtService = jwtService;
    }

    /** Register: check duplicate -> hash password -> save. Always role USER (never trust client for role). */
    public UserResponse register(RegisterRequest req) {
        if (userRepository.existsByEmail(req.email())) {
            throw new ApiException(HttpStatus.CONFLICT, "Email already registered");
        }
        User user = new User(req.name(), req.email(),
                passwordEncoder.encode(req.password()), Role.USER);
        User saved = userRepository.save(user);
        return new UserResponse(saved.getId(), saved.getName(), saved.getEmail(), saved.getRole().name());
    }

    /**
     * Login:
     *  1. authenticationManager.authenticate() -> DaoAuthenticationProvider
     *       -> loadUserByUsername(email) -> passwordEncoder.matches(raw, hash)
     *     Throws BadCredentialsException if wrong (handled -> 401).
     *  2. Generate access + refresh tokens and return them.
     */
    public AuthResponse login(LoginRequest req) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.email(), req.password()));

        UserDetails userDetails = userDetailsService.loadUserByUsername(req.email());
        return buildAuthResponse(userDetails, jwtService.generateRefreshToken(userDetails));
    }

    /** Refresh: valid refresh token -> new access token (user does not re-enter password). */
    public AuthResponse refresh(RefreshRequest req) {
        String refreshToken = req.refreshToken();
        try {
            String email = jwtService.extractUsername(refreshToken);
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);
            if (!jwtService.isTokenValid(refreshToken, userDetails, JwtService.TOKEN_TYPE_REFRESH)) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
            }
            return buildAuthResponse(userDetails, refreshToken);
        } catch (JwtException | IllegalArgumentException e) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
        }
    }

    private AuthResponse buildAuthResponse(UserDetails userDetails, String refreshToken) {
        String role = userDetails.getAuthorities().iterator().next().getAuthority().replace("ROLE_", "");
        return new AuthResponse(
                jwtService.generateAccessToken(userDetails),
                refreshToken,
                "Bearer",
                jwtService.getAccessExpirationMs(),
                userDetails.getUsername(),
                role);
    }
}
