package com.demo.jwtauth.entity;

/**
 * Roles are stored WITHOUT the "ROLE_" prefix.
 * Spring adds/expects "ROLE_" when we use hasRole("ADMIN") — so we add it
 * when building authorities (see CustomUserDetailsService).
 */
public enum Role {
    USER,
    ADMIN
}
