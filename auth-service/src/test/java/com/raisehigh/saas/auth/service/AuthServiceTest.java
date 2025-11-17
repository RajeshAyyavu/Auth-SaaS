package com.raisehigh.saas.auth.service;

import com.raisehigh.saas.auth.domain.RefreshToken;
import com.raisehigh.saas.auth.domain.Role;
import com.raisehigh.saas.auth.domain.User;
import com.raisehigh.saas.auth.dto.*;
import com.raisehigh.saas.auth.exceptions.DuplicateEmailException;
import com.raisehigh.saas.auth.exceptions.InvalidCredentialsException;
import com.raisehigh.saas.auth.exceptions.InvalidTokenException;
import com.raisehigh.saas.auth.exceptions.UserNotFoundException;
import com.raisehigh.saas.auth.repository.UserRepository;
import com.raisehigh.saas.auth.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private AuthenticationManager authenticationManager;

    private AuthService authService;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);

        authService = new AuthService(
                userRepository,
                passwordEncoder,
                jwtService,
                refreshTokenService,
                authenticationManager
        );
    }

    // ===================== SIGNUP =====================

    @Test
    void signup_ShouldThrowException_WhenEmailAlreadyExists() {
        SignupRequest req = SignupRequest.builder()
                .email("test@example.com")
                .password("password123")
                .fullName("Rajesh")
                .build();

        when(userRepository.existsByEmail(req.getEmail())).thenReturn(true);

        assertThrows(DuplicateEmailException.class,
                () -> authService.signup(req));
    }

    @Test
    void signup_ShouldSaveUser_WhenValidRequest() {
        SignupRequest req = SignupRequest.builder()
                .email("new@example.com")
                .password("password123")
                .fullName("Rajesh")
                .build();

        when(userRepository.existsByEmail(req.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(req.getPassword())).thenReturn("encoded-password");

        User savedUser = User.builder()
                .id(UUID.randomUUID())
                .email(req.getEmail())
                .password("encoded-password")
                .role(Role.USER)
                .enabled(true)
                .emailVerified(false)
                .accountNonLocked(true)
                .build();

        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        when(jwtService.generateToken(any(User.class))).thenReturn("mock-access");
        when(refreshTokenService.create(any(User.class)))
                .thenReturn(RefreshToken.builder().token("mock-refresh").build());

        AuthResponse response = authService.signup(req);

        assertEquals("mock-access", response.getAccessToken());
        assertEquals("mock-refresh", response.getRefreshToken());
    }

    // ===================== LOGIN =====================

    @Test
    void login_ShouldThrowInvalidCredentials_WhenPasswordWrong() {
        LoginRequest req = new LoginRequest("user@example.com", "wrong");

        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Bad creds"));

        assertThrows(InvalidCredentialsException.class,
                () -> authService.login(req));
    }

    @Test
    void login_ShouldReturnTokens_WhenCredentialsAreValid() {
        LoginRequest req = new LoginRequest("user@example.com", "pass");

        User user = User.builder()
                .id(UUID.randomUUID())
                .email(req.getEmail())
                .role(Role.USER)
                .enabled(true)
                .accountNonLocked(true)
                .build();

        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(user);
        when(authenticationManager.authenticate(any())).thenReturn(auth);

        when(jwtService.generateToken(any(User.class))).thenReturn("access-token");
        when(refreshTokenService.create(any(User.class)))
                .thenReturn(RefreshToken.builder().token("refresh-token").build());

        AuthResponse response = authService.login(req);

        assertEquals("access-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());
    }

    // ===================== REFRESH TOKEN =====================

    @Test
    void refreshAccessToken_ShouldThrowException_WhenTokenInvalid() {
        when(jwtService.validate("bad-token")).thenReturn(false);

        RefreshTokenRequest req = RefreshTokenRequest.builder()
                .refreshToken("bad-token")
                .build();

        assertThrows(InvalidTokenException.class,
                () -> authService.refreshAccessToken(req));
    }

    @Test
    void refreshAccessToken_ShouldThrowException_WhenUserNotFound() {
        UUID uid = UUID.randomUUID();

        RefreshTokenRequest req = RefreshTokenRequest.builder()
                .refreshToken("valid-token")
                .build();

        when(jwtService.validate("valid-token")).thenReturn(true);
        when(jwtService.extractUserId("valid-token")).thenReturn(uid);
        doNothing().when(refreshTokenService).verifyRefreshToken("valid-token");

        when(userRepository.findById(uid)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class,
                () -> authService.refreshAccessToken(req));
    }

    @Test
    void refreshAccessToken_ShouldReturnNewAccessToken_WhenValid() {
        UUID uid = UUID.randomUUID();

        RefreshTokenRequest req = RefreshTokenRequest.builder()
                .refreshToken("valid-token")
                .build();

        when(jwtService.validate("valid-token")).thenReturn(true);
        when(jwtService.extractUserId("valid-token")).thenReturn(uid);
        doNothing().when(refreshTokenService).verifyRefreshToken("valid-token");

        User user = User.builder()
                .id(uid)
                .email("user@example.com")
                .role(Role.USER)
                .enabled(true)
                .accountNonLocked(true)
                .build();

        when(userRepository.findById(uid)).thenReturn(Optional.of(user));
        when(jwtService.generateToken(user)).thenReturn("new-access");

        RefreshTokenResponse res = authService.refreshAccessToken(req);

        assertEquals("new-access", res.getAccessToken());
        assertEquals("valid-token", res.getRefreshToken());
    }

    // ===================== CURRENT USER =====================

    @Test
    void getCurrentUser_ShouldThrowException_WhenNoAuth() {
        SecurityContextHolder.clearContext();
        assertThrows(InvalidCredentialsException.class,
                () -> authService.getCurrentUser());
    }
}
