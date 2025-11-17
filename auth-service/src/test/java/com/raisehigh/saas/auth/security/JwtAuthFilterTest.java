package com.raisehigh.saas.auth.security;

import com.raisehigh.saas.auth.domain.Role;
import com.raisehigh.saas.auth.domain.User;
import com.raisehigh.saas.auth.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthFilterTest {

    @Mock private JwtService jwtService;
    @Mock private UserRepository userRepository;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain filterChain;

    private JwtAuthFilter jwtAuthFilter;

    private User mockUser;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);

        jwtAuthFilter = new JwtAuthFilter(jwtService, userRepository);

        mockUser = User.builder()
                .id(UUID.randomUUID())
                .email("user@example.com")
                .password("pass123")
                .role(Role.USER)
                .enabled(true)                // REQUIRED
                .emailVerified(true)          // OPTIONAL but safe
                .accountNonLocked(true)
                .build();

        SecurityContextHolder.clearContext();
    }

    // --------------------------------------------------------------------
    // 1) No Authorization header → SKIP FILTER
    // --------------------------------------------------------------------
    @Test
    void shouldSkipFilter_WhenNoAuthorizationHeader() throws Exception {

        when(request.getHeader("Authorization")).thenReturn(null);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        verify(jwtService, never()).validate(anyString());
        verify(filterChain).doFilter(request, response);
    }

    // --------------------------------------------------------------------
    // 2) Invalid token → SKIP AUTHENTICATION
    // --------------------------------------------------------------------
    @Test
    void shouldNotAuthenticate_WhenTokenInvalid() throws Exception {

        when(request.getHeader("Authorization")).thenReturn("Bearer invalid-token");
        when(jwtService.validate("invalid-token")).thenReturn(false);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    // --------------------------------------------------------------------
    // 3) Valid token → authenticate user
    // --------------------------------------------------------------------
    @Test
    void shouldAuthenticateUser_WhenTokenValid() throws Exception {

        UUID userId = mockUser.getId();

        when(request.getHeader("Authorization")).thenReturn("Bearer valid-token");
        when(jwtService.validate("valid-token")).thenReturn(true);
        when(jwtService.extractUserId("valid-token")).thenReturn(userId);

        when(userRepository.findById(userId)).thenReturn(Optional.of(mockUser));

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal())
                .isEqualTo(mockUser);

        verify(filterChain).doFilter(request, response);
    }

    // --------------------------------------------------------------------
    // 4) Already authenticated → do NOT authenticate again
    // --------------------------------------------------------------------
    @Test
    void shouldNotReAuthenticate_WhenAlreadyAuthenticated() throws Exception {

        SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        mockUser, null, mockUser.getAuthorities())
        );

        when(request.getHeader("Authorization")).thenReturn("Bearer another-token");
        when(jwtService.validate("another-token")).thenReturn(true);

        jwtAuthFilter.doFilterInternal(request, response, filterChain);

        verify(jwtService, never()).extractUserId(anyString());
        verify(userRepository, never()).findById(any());
    }

    // --------------------------------------------------------------------
    // 5) Public endpoints → shouldNotFilter = true
    // --------------------------------------------------------------------
    @Test
    void shouldNotFilter_ForPublicEndpoints() {
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");

        boolean result = jwtAuthFilter.shouldNotFilter(request);

        assertThat(result).isTrue();
    }
}
