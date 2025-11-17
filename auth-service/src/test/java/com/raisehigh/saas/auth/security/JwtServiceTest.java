package com.raisehigh.saas.auth.security;

import com.raisehigh.saas.auth.domain.Role;
import com.raisehigh.saas.auth.domain.User;
import io.jsonwebtoken.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private JwtService jwtService;

    private String SECRET;
    private final long EXPIRATION_MS = 1000 * 60 * 15; // 15 mins
    private final long REFRESH_EXPIRATION_MS = 1000L * 60 * 60 * 24 * 7;

    private User testUser;

    @BeforeEach
    void setup() {

        // --------------------------
        //  Generate secure key (256-bit)
        // --------------------------
        SECRET = Base64.getEncoder().encodeToString(
                Jwts.SIG.HS256.key().build().getEncoded()
        );

        jwtService = new JwtService();
        inject(jwtService, "secret", SECRET);
        inject(jwtService, "expirationMs", EXPIRATION_MS);
        inject(jwtService, "refreshExpirationMs", REFRESH_EXPIRATION_MS);

        testUser = User.builder()
                .id(UUID.randomUUID())
                .email("user@example.com")
                .fullName("Rajesh Ayyavu")
                .role(Role.USER)
                .build();
    }

    private void inject(Object target, String field, Object value) {
        try {
            var f = target.getClass().getDeclaredField(field);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    // ------------------------------------------------------
    // 1. Test: valid token created
    // ------------------------------------------------------
    @Test
    void generateToken_ShouldReturnValidJwt() {
        String token = jwtService.generateToken(testUser);

        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);
        assertTrue(jwtService.validate(token));
    }

    // ------------------------------------------------------
    // 2. Test: tampered token should fail validation
    // ------------------------------------------------------
    @Test
    void validate_ShouldReturnFalse_ForTamperedToken() {
        String token = jwtService.generateToken(testUser);
        String tampered = token.substring(0, token.length() - 2) + "xx";

        assertFalse(jwtService.validate(tampered));
    }

    // ------------------------------------------------------
    // 3. Test: wrong secret key
    // ------------------------------------------------------
    @Test
    void validate_ShouldReturnFalse_WhenWrongSecretUsed() {

        String token = jwtService.generateToken(testUser);

        JwtService wrongJwt = new JwtService();
        String wrongSecret = Base64.getEncoder().encodeToString(
                Jwts.SIG.HS256.key().build().getEncoded()
        );

        inject(wrongJwt, "secret", wrongSecret);
        inject(wrongJwt, "expirationMs", EXPIRATION_MS);
        inject(wrongJwt, "refreshExpirationMs", REFRESH_EXPIRATION_MS);

        assertFalse(wrongJwt.validate(token));
    }

    // ------------------------------------------------------
    // 4. Test: expired token
    // ------------------------------------------------------
    @Test
    void isTokenExpired_ShouldReturnTrue_WhenExpired() throws Exception {
        JwtService shortExpiry = new JwtService();
        inject(shortExpiry, "secret", SECRET);
        inject(shortExpiry, "expirationMs", 1);
        inject(shortExpiry, "refreshExpirationMs", REFRESH_EXPIRATION_MS);

        String token = shortExpiry.generateToken(testUser);
        Thread.sleep(5);

        assertTrue(shortExpiry.isTokenExpired(token));
    }

    // ------------------------------------------------------
    // 5. Test: extract user ID
    // ------------------------------------------------------
    @Test
    void extractUserId_ShouldReturnCorrectUUID() {
        String token = jwtService.generateToken(testUser);
        assertEquals(testUser.getId(), jwtService.extractUserId(token));
    }

    // ------------------------------------------------------
    // 6. Test: extract email
    // ------------------------------------------------------
    @Test
    void extractEmail_ShouldReturnCorrectEmail() {
        String token = jwtService.generateToken(testUser);
        assertEquals("user@example.com", jwtService.extractEmail(token));
    }

    // ------------------------------------------------------
    // 7. Test: extract role
    // ------------------------------------------------------
    @Test
    void extractRole_ShouldReturnCorrectRole() {
        String token = jwtService.generateToken(testUser);
        assertEquals("USER", jwtService.extractRole(token));
    }

    // ------------------------------------------------------
    // 8. Test: invalid / malformed token
    // ------------------------------------------------------
    @Test
    void validate_ShouldReturnFalse_ForMalformedToken() {
        assertFalse(jwtService.validate("invalid-token"));
    }

    // ------------------------------------------------------
    // 9. Test: performance (<50ms)
    // ------------------------------------------------------
    @Test
    void generateToken_ShouldBeFastUnder50ms() {
        long t1 = System.currentTimeMillis();
        jwtService.generateToken(testUser);
        long t2 = System.currentTimeMillis();

        assertTrue((t2 - t1) < 50);
    }

}
