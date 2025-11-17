package com.raisehigh.saas.auth.service;

import com.raisehigh.saas.auth.domain.RefreshToken;
import com.raisehigh.saas.auth.domain.User;
import com.raisehigh.saas.auth.dto.RefreshTokenRequest;
import com.raisehigh.saas.auth.dto.RefreshTokenResponse;
import com.raisehigh.saas.auth.exceptions.InvalidTokenException;
import com.raisehigh.saas.auth.repository.RefreshTokenRepository;
import com.raisehigh.saas.auth.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    @Value("${app.jwt.refresh-expiration-ms}")
    private long refreshExpirationMs;

    /**
     * Create a new refresh token (one per user)
     */
    public RefreshToken create(User user) {
        // Only one refresh token per user
        refreshTokenRepository.deleteByUser(user);

        RefreshToken token = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .expiry(Instant.now().plusMillis(refreshExpirationMs))
                .user(user)
                .build();

        return refreshTokenRepository.save(token);
    }

    /**
     * Delete refresh token by token string
     */
    public void deleteByToken(String refreshToken) {
        refreshTokenRepository.deleteByToken(refreshToken);
    }

    /**
     * Validate refresh token (exists + not expired)
     */
    public void verifyRefreshToken(String refreshToken) {
        RefreshToken token = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        if (token.isExpired()) {
            refreshTokenRepository.delete(token);
            throw new InvalidTokenException("Refresh token expired");
        }
    }

    /**
     * Rotate refresh token (generate new access token)
     */
    public RefreshTokenResponse rotateToken(RefreshTokenRequest request) {

        String refreshToken = request.getRefreshToken();

        // Validate JWT signature + expiry
        if (!jwtService.validate(refreshToken)) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        UUID userId = jwtService.extractUserId(refreshToken);

        RefreshToken savedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        if (savedToken.isExpired()) {
            refreshTokenRepository.delete(savedToken);
            throw new InvalidTokenException("Refresh token expired");
        }

        User user = savedToken.getUser();

        // New access token (refresh token remains same)
        String accessToken = jwtService.generateToken(user);

        return RefreshTokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .build();
    }
}
