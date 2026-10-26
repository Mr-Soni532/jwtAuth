package com.demo.jwtauth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * All request/response DTOs in one file (Java records = immutable, no boilerplate).
 * Never expose the User entity directly — it contains the password hash.
 */
public final class AuthDtos {

    private AuthDtos() {}

    public record RegisterRequest(
            @NotBlank(message = "Name is required") String name,
            @NotBlank @Email(message = "Invalid email") String email,
            @NotBlank @Size(min = 6, message = "Password must be at least 6 characters") String password
    ) {}

    public record LoginRequest(
            @NotBlank @Email String email,
            @NotBlank String password
    ) {}

    public record RefreshRequest(
            @NotBlank String refreshToken
    ) {}

    public record AuthResponse(
            String accessToken,
            String refreshToken,
            String tokenType,
            long expiresInMs,
            String email,
            String role
    ) {}

    public record UserResponse(
            Long id,
            String name,
            String email,
            String role
    ) {}

    public record MessageResponse(String message) {}
}
