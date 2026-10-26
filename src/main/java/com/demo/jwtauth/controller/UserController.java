package com.demo.jwtauth.controller;

import com.demo.jwtauth.dto.AuthDtos.UserResponse;
import com.demo.jwtauth.entity.User;
import com.demo.jwtauth.exception.ApiException;
import com.demo.jwtauth.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PROTECTED: any logged-in user (USER or ADMIN) with a valid access token.
 */
@RestController
@RequestMapping("/api/user")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * @AuthenticationPrincipal gives us the UserDetails that JwtAuthFilter put
     * into the SecurityContext — i.e. "who is calling" — no need to parse the token again.
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal UserDetails principal) {
        User user = userRepository.findByEmail(principal.getUsername())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        return ResponseEntity.ok(new UserResponse(
                user.getId(), user.getName(), user.getEmail(), user.getRole().name()));
    }
}
