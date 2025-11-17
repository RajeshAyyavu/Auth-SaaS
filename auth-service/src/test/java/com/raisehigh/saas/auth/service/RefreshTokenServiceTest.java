package com.raisehigh.saas.auth.service;

import com.raisehigh.saas.auth.domain.RefreshToken;
import com.raisehigh.saas.auth.domain.User;
import com.raisehigh.saas.auth.exceptions.InvalidTokenException;
import com.raisehigh.saas.auth.repository.RefreshTokenRepository;
import com.raisehigh.saas.auth.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private RefreshTokenService refreshTokenService;

    private JwtService jwtService;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
        refreshTokenService = new RefreshTokenService(
                refreshTokenRepository,
                jwtService
        );
    }

    // ---------------------- CREATE TOKEN ----------------------
    @Test
    void create_ShouldDeleteOldTokens_AndSaveNewToken() {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("user@example.com")
                .build();

        RefreshToken savedToken = RefreshToken.builder()
                .token("new-token-123")
                .user(user)
                .expiry(Instant.now().plusSeconds(3600))
                .build();

        when(refreshTokenRepository.save(any())).thenReturn(savedToken);

        RefreshToken result = refreshTokenService.create(user);

        verify(refreshTokenRepository, times(1)).deleteByUser(user);
        verify(refreshTokenRepository, times(1)).save(any());
        assertEquals("new-token-123", result.getToken());
    }

    // ---------------------- VERIFY TOKEN ----------------------
    @Test
    void verifyRefreshToken_ShouldThrow_WhenTokenNotFound() {
        when(refreshTokenRepository.findByToken("abc")).thenReturn(Optional.empty());

        assertThrows(InvalidTokenException.class, () ->
                refreshTokenService.verifyRefreshToken("abc")
        );
    }

    @Test
    void verifyRefreshToken_ShouldThrow_WhenTokenExpired() {
        RefreshToken expired = RefreshToken.builder()
                .token("expired")
                .expiry(Instant.now().minusSeconds(10))
                .build();

        when(refreshTokenRepository.findByToken("expired")).thenReturn(Optional.of(expired));

        assertThrows(InvalidTokenException.class, () ->
                refreshTokenService.verifyRefreshToken("expired")
        );
    }

    @Test
    void verifyRefreshToken_ShouldPass_WhenValidToken() {
        RefreshToken valid = RefreshToken.builder()
                .token("valid")
                .expiry(Instant.now().plusSeconds(3600))
                .build();

        when(refreshTokenRepository.findByToken("valid"))
                .thenReturn(Optional.of(valid));

        assertDoesNotThrow(() ->
                refreshTokenService.verifyRefreshToken("valid")
        );
    }

    // ---------------------- DELETE TOKEN ----------------------
    @Test
    void deleteByToken_ShouldCallRepository() {
        refreshTokenService.deleteByToken("xyz");

        verify(refreshTokenRepository, times(1)).deleteByToken("xyz");
    }
}
