package com.demo.jwtauth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

/**
 * STEP: JWT utility — generate, parse and validate tokens.
 *
 * JWT = header.payload.signature  (each part Base64URL-encoded)
 *   header    -> {"alg":"HS256","typ":"JWT"}
 *   payload   -> claims: sub (email), role, type, iat, exp
 *   signature -> HMACSHA256(header + "." + payload, secretKey)
 *
 * The payload is only ENCODED, not encrypted -> never put passwords/secrets in it.
 * The signature guarantees nobody tampered with it (integrity), because only the
 * server knows the secret key.
 */
@Service
public class JwtService {

    public static final String TOKEN_TYPE_ACCESS = "access";
    public static final String TOKEN_TYPE_REFRESH = "refresh";

    private final SecretKey signingKey;
    private final long accessExpirationMs;
    private final long refreshExpirationMs;

    public JwtService(@Value("${app.jwt.secret}") String base64Secret,
                      @Value("${app.jwt.access-expiration-ms}") long accessExpirationMs,
                      @Value("${app.jwt.refresh-expiration-ms}") long refreshExpirationMs) {
        // Build the HMAC key once (HS256 requires >= 256-bit key)
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
        this.accessExpirationMs = accessExpirationMs;
        this.refreshExpirationMs = refreshExpirationMs;
    }

    // ---------------------------------------------------------------- generate

    public String generateAccessToken(UserDetails user) {
        String role = user.getAuthorities().iterator().next().getAuthority(); // e.g. ROLE_USER
        return buildToken(user.getUsername(),
                Map.of("role", role, "type", TOKEN_TYPE_ACCESS),
                accessExpirationMs);
    }

    public String generateRefreshToken(UserDetails user) {
        // Refresh token carries minimum info — only used to get a new access token
        return buildToken(user.getUsername(), Map.of("type", TOKEN_TYPE_REFRESH), refreshExpirationMs);
    }

    private String buildToken(String subject, Map<String, Object> extraClaims, long expiryMs) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .claims(extraClaims)
                .subject(subject)                       // "sub" = who the token belongs to
                .issuedAt(new Date(now))                // "iat"
                .expiration(new Date(now + expiryMs))   // "exp"
                .signWith(signingKey)                   // HS256/384/512 auto-picked from key size
                .compact();
    }

    // ---------------------------------------------------------------- read / validate

    /** Parses token AND verifies signature + expiry. Throws JwtException if invalid/expired. */
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String extractTokenType(String token) {
        return extractAllClaims(token).get("type", String.class);
    }

    /** Valid = signature OK + not expired (checked by parser) + belongs to this user + expected type. */
    public boolean isTokenValid(String token, UserDetails user, String expectedType) {
        try {
            Claims claims = extractAllClaims(token);
            return claims.getSubject().equals(user.getUsername())
                    && expectedType.equals(claims.get("type", String.class));
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public long getAccessExpirationMs() {
        return accessExpirationMs;
    }
}
