package com.raisehigh.saas.auth.security;

import com.raisehigh.saas.auth.domain.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    /**
     * -- GETTER --
     *  Get token expiration time in milliseconds
     */
    @Getter
    @Value("${app.jwt.expiration-ms}")
    private long expirationMs;

    /**
     * -- GETTER --
     *  Get refresh token expiration time in milliseconds
     */
    @Getter
    @Value("${app.jwt.refresh-expiration-ms:#{7 * 24 * 60 * 60 * 1000}}")  // Default 7 days
    private long refreshExpirationMs;

    private SecretKey getSigningKey() {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Generate access token for authenticated user
     */
    public String generateToken(User user) {
        return generateToken(user.getId(), user.getEmail(), user.getRole().name(), expirationMs);
    }

    /**
     * Generate refresh token with longer expiration
     */
    public String generateRefreshToken(User user) {
        return generateToken(user.getId(), user.getEmail(), user.getRole().name(), refreshExpirationMs);
    }

    /**
     * Core token generation method
     */
    private String generateToken(UUID userId, String email, String role, long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Validate token signature and expiration
     */
    public boolean validate(String token) {
        try {
            parse(token);
            return true;

        } catch (ExpiredJwtException e) {
            return false;

        } catch (MalformedJwtException e) {
            return false;

        } catch (SecurityException e) { // older signature exceptions
            return false;

        } catch (io.jsonwebtoken.security.SignatureException e) { // required for JJWT 0.12.x
            return false;

        } catch (JwtException e) { // any other JWT parsing error
            return false;

        } catch (IllegalArgumentException e) { // null, empty, etc.
            return false;
        }
    }


    /**
     * Check if token is expired
     */
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = parse(token).getPayload().getExpiration();
            return expiration.before(new Date());
        } catch (JwtException e) {
            return true;
        }
    }

    /**
     * Parse and verify JWT token
     */
    private Jws<Claims> parse(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token);
    }

    /**
     * Extract user ID as UUID
     */
    public UUID extractUserId(String token) {
        String subject = parse(token).getPayload().getSubject();
        return UUID.fromString(subject);
    }

    /**
     * Extract user ID as String (for backward compatibility)
     */
    public String extractUserIdAsString(String token) {
        return parse(token).getPayload().getSubject();
    }

    /**
     * Extract email from token
     */
    public String extractEmail(String token) {
        return parse(token).getPayload().get("email", String.class);
    }

    /**
     * Extract role from token
     */
    public String extractRole(String token) {
        return parse(token).getPayload().get("role", String.class);
    }

    /**
     * Extract all claims from token
     */
    public Claims extractAllClaims(String token) {
        return parse(token).getPayload();
    }

}