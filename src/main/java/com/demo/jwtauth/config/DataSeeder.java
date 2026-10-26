package com.demo.jwtauth.config;

import com.demo.jwtauth.entity.Role;
import com.demo.jwtauth.entity.User;
import com.demo.jwtauth.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Creates a default ADMIN on startup (register API always creates USER).
 * Login: admin@demo.com / admin123
 */
@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner seedAdmin(UserRepository repo, PasswordEncoder encoder) {
        return args -> {
            if (!repo.existsByEmail("admin@demo.com")) {
                repo.save(new User("Admin", "admin@demo.com", encoder.encode("admin123"), Role.ADMIN));
            }
        };
    }
}
