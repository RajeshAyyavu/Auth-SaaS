package com.raisehigh.saas.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.raisehigh.saas.auth.domain.Role;
import com.raisehigh.saas.auth.dto.*;
import com.raisehigh.saas.auth.service.AuthService;
import com.raisehigh.saas.auth.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    private MockMvc mockMvc;

    @Mock
    private AuthService authService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private AuthController authController;

    private ObjectMapper objectMapper;
    private SignupRequest signupRequest;
    private AuthResponse authResponse;

    @BeforeEach
    void setup() {
        objectMapper = new ObjectMapper();
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();

        signupRequest = SignupRequest.builder()
                .email("test@example.com")
                .password("password123")
                .fullName("Test User")
                .build();

        UserDto userDto = UserDto.builder()
                .id(UUID.randomUUID().toString())
                .email("test@example.com")
                .fullName("Test User")
                .role(Role.USER)
                .createdAt(LocalDateTime.now())
                .emailVerified(false)
                .build();

        authResponse = AuthResponse.builder()
                .accessToken("access-token-123")
                .refreshToken("refresh-token-456")
                .tokenType("Bearer")
                .expiresIn(3600L)
                .user(userDto)
                .build();
    }

    @Test
    void signup_ShouldReturn200_WhenRequestValid() throws Exception {
        when(authService.signup(any(SignupRequest.class)))
                .thenReturn(authResponse);

        mockMvc.perform(post("/api/v1/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("access-token-123"));
    }

    @Test
    void login_ShouldReturn200_WhenCredentialsValid() throws Exception {
        LoginRequest loginReq = LoginRequest.builder()
                .email("test@example.com")
                .password("password123")
                .build();

        when(authService.login(any(LoginRequest.class)))
                .thenReturn(authResponse);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.refreshToken").value("refresh-token-456"));
    }

    @Test
    void refresh_ShouldReturn200_WhenRefreshTokenValid() throws Exception {
        RefreshTokenRequest req = new RefreshTokenRequest("valid-refresh-token");

        RefreshTokenResponse refreshResponse = RefreshTokenResponse.builder()
                .accessToken("new-access-789")
                .refreshToken("valid-refresh-token")
                .tokenType("Bearer")
                .build();

        when(refreshTokenService.rotateToken(any(RefreshTokenRequest.class)))
                .thenReturn(refreshResponse);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("new-access-789"));
    }

    @Test
    void me_ShouldReturn200_WithUserDto() throws Exception {
        UserDto userDto = UserDto.builder()
                .id(UUID.randomUUID().toString())
                .email("me@example.com")
                .fullName("My Self")
                .role(Role.USER)
                .createdAt(LocalDateTime.now())
                .emailVerified(true)
                .build();

        when(authService.getCurrentUserDto()).thenReturn(userDto);

        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.email").value("me@example.com"));
    }

    @Test
    void signup_ShouldReturn400_WhenInvalidJson() throws Exception {
        mockMvc.perform(post("/api/v1/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ bad json }"))
                .andExpect(status().isBadRequest());
    }
}