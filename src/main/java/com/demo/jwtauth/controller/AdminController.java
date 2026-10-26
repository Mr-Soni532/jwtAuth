package com.demo.jwtauth.controller;

import com.demo.jwtauth.dto.AuthDtos.UserResponse;
import com.demo.jwtauth.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * PROTECTED + ROLE-BASED: only ADMIN.
 * Protected twice to show both styles:
 *   - URL rule in SecurityConfig: .requestMatchers("/api/admin/**").hasRole("ADMIN")
 *   - Method-level: @PreAuthorize (needs @EnableMethodSecurity)
 * A USER token here -> 403 Forbidden.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserRepository userRepository;

    public AdminController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponse>> allUsers() {
        return ResponseEntity.ok(userRepository.findAll().stream()
                .map(u -> new UserResponse(u.getId(), u.getName(), u.getEmail(), u.getRole().name()))
                .toList());
    }
}
