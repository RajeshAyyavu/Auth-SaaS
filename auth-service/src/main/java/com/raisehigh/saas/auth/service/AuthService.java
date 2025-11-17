package com.raisehigh.saas.auth.service;

import com.raisehigh.saas.auth.domain.Role;
import com.raisehigh.saas.auth.domain.User;
import com.raisehigh.saas.auth.dto.*;
import com.raisehigh.saas.auth.exceptions.DuplicateEmailException;
import com.raisehigh.saas.auth.exceptions.InvalidCredentialsException;
import com.raisehigh.saas.auth.exceptions.InvalidTokenException;
import com.raisehigh.saas.auth.exceptions.UserNotFoundException;
import com.raisehigh.saas.auth.repository.UserRepository;
import com.raisehigh.saas.auth.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;

    /**
     * Register a new user
     */
    @Transactional
    public AuthResponse signup(SignupRequest req) {
        log.info("Signup attempt for email: {}", req.getEmail());

        // Validate email uniqueness
        if (userRepository.existsByEmail(req.getEmail())) {
            log.warn("Signup failed - email already exists: {}", req.getEmail());
            throw new DuplicateEmailException("Email already registered: " + req.getEmail());
        }

        // Validate password strength (optional - can be done with validation annotations)
        validatePassword(req.getPassword());

        // Create new user
        User user = User.builder()
                .email(req.getEmail().toLowerCase().trim()) // Normalize email
                .password(passwordEncoder.encode(req.getPassword()))
                .fullName(req.getFullName())
                .role(Role.USER)
                .enabled(true)
                .emailVerified(false) // Require email verification in production
                .accountNonLocked(true)
                .build();

        user = userRepository.save(user);

        log.info("User registered successfully: {} with ID: {}", user.getEmail(), user.getId());

        // TODO: Send verification email in production
        // emailService.sendVerificationEmail(user);

        return generateTokens(user);
    }

    /**
     * Authenticate user and generate tokens
     */
    @Transactional
    public AuthResponse login(LoginRequest req) {
        log.info("Login attempt for email: {}", req.getEmail());

        try {
            // Use Spring Security's AuthenticationManager for authentication
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            req.getEmail().toLowerCase().trim(),
                            req.getPassword()
                    )
            );

            User user = (User) authentication.getPrincipal();

            // Additional security checks
            if (!user.isEnabled()) {
                log.warn("Login failed - account disabled: {}", user.getEmail());
                throw new InvalidCredentialsException("Account is disabled");
            }

            if (!user.isAccountNonLocked()) {
                log.warn("Login failed - account locked: {}", user.getEmail());
                throw new InvalidCredentialsException("Account is locked");
            }

            // Update last login timestamp
            user.setLastLoginAt(LocalDateTime.now());
            userRepository.save(user);

            log.info("User logged in successfully: {}", user.getEmail());

            return generateTokens(user);

        } catch (BadCredentialsException e) {
            log.warn("Login failed - invalid credentials for email: {}", req.getEmail());
            throw new InvalidCredentialsException("Invalid email or password");
        }
    }

    /**
     * Refresh access token using refresh token
     */
    @Transactional
    public RefreshTokenResponse refreshAccessToken(RefreshTokenRequest req) {
        log.info("Token refresh attempt");

        String refreshToken = req.getRefreshToken();

        // Validate refresh token
        if (!jwtService.validate(refreshToken)) {
            log.warn("Invalid refresh token provided");
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        // Extract user ID from refresh token
        UUID userId = jwtService.extractUserId(refreshToken);

        // Verify refresh token exists in database
        refreshTokenService.verifyRefreshToken(refreshToken);

        // Get user and generate new access token
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!user.isEnabled() || !user.isAccountNonLocked()) {
            log.warn("Token refresh denied - account disabled or locked: {}", user.getEmail());
            throw new InvalidCredentialsException("Account is disabled or locked");
        }

        String newAccessToken = jwtService.generateToken(user);

        log.info("Access token refreshed for user: {}", user.getEmail());

        return RefreshTokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken) // Return same refresh token
                .build();
    }

    /**
     * Logout user by invalidating refresh token
     */
    @Transactional
    public void logout(String refreshToken) {
        log.info("Logout attempt");

        if (refreshToken != null && jwtService.validate(refreshToken)) {
            refreshTokenService.deleteByToken(refreshToken);
            log.info("User logged out successfully");
        }

        SecurityContextHolder.clearContext();
    }

    /**
     * Get current authenticated user
     */
    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InvalidCredentialsException("User not authenticated");
        }

        return (User) authentication.getPrincipal();
    }

    /**
     * Generate both access and refresh tokens
     */
    private AuthResponse generateTokens(User user) {
        String accessToken = jwtService.generateToken(user);
        String refreshToken = refreshTokenService.create(user).getToken();

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getExpirationMs() / 1000) // Convert to seconds
                .user(mapToUserDto(user))
                .build();
    }

    /**
     * Map User entity to UserDto
     */
    private UserDto mapToUserDto(User user) {
        return UserDto.builder()
                .id(user.getId().toString())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .role(user.getRole())
                .emailVerified(user.getEmailVerified())
                .createdAt(user.getCreatedAt())
                .build();
    }

    /**
     * Validate password strength (basic implementation)
     */
    private void validatePassword(String password) {
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }

        // Add more validation rules as needed:
        // - Must contain uppercase
        // - Must contain lowercase
        // - Must contain number
        // - Must contain special character
    }

    public UserDto getCurrentUserDto() {
        User user = getCurrentUser(); // fetch from SecurityContext
        return mapToUserDto(user);    // convert to DTO
    }
}