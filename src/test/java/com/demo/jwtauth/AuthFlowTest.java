package com.demo.jwtauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * End-to-end test of the whole flow: register -> login -> protected -> role check -> refresh.
 * Run: mvn test
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    private String login(String email, String password) throws Exception {
        String res = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return res;
    }

    @Test
    void fullFlow() throws Exception {
        // Register
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Raj\",\"email\":\"raj@test.com\",\"password\":\"secret123\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist());

        // Duplicate register -> 409
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Raj\",\"email\":\"raj@test.com\",\"password\":\"secret123\"}"))
                .andExpect(status().isConflict());

        // Validation -> 400
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"\",\"email\":\"bad\",\"password\":\"1\"}"))
                .andExpect(status().isBadRequest());

        // Wrong password -> 401
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"raj@test.com\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized());

        // Login OK
        JsonNode auth = om.readTree(login("raj@test.com", "secret123"));
        String access = auth.get("accessToken").asText();
        String refresh = auth.get("refreshToken").asText();

        // No token -> 401
        mvc.perform(get("/api/user/me")).andExpect(status().isUnauthorized());

        // Garbage token -> 401
        mvc.perform(get("/api/user/me").header("Authorization", "Bearer abc.def.ghi"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid token"));

        // Valid token -> 200
        mvc.perform(get("/api/user/me").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("raj@test.com"));

        // Refresh token must NOT work as access token
        mvc.perform(get("/api/user/me").header("Authorization", "Bearer " + refresh))
                .andExpect(status().isUnauthorized());

        // USER on admin endpoint -> 403
        mvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + access))
                .andExpect(status().isForbidden());

        // ADMIN on admin endpoint -> 200
        String adminAccess = om.readTree(login("admin@demo.com", "admin123")).get("accessToken").asText();
        mvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk());

        // Refresh -> new access token
        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists());

        // Access token used as refresh -> 401
        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + access + "\"}"))
                .andExpect(status().isUnauthorized());
    }
}
