package com.raisehigh.saas.auth.controller;

import com.raisehigh.saas.auth.dto.*;
import com.raisehigh.saas.auth.service.AuthService;
import com.raisehigh.saas.auth.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    // ---------------- SIGNUP ----------------
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<AuthResponse>> signup(@RequestBody SignupRequest request) {
        AuthResponse response = authService.signup(request);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    // ---------------- LOGIN -----------------
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    // ---------------- REFRESH TOKEN ---------
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<RefreshTokenResponse>> refresh(
            @RequestBody RefreshTokenRequest request
    ) {
        RefreshTokenResponse response = refreshTokenService.rotateToken(request);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    // ---------------- CURRENT USER ----------
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserDto>> me() {
        UserDto userDto = authService.getCurrentUserDto(); // <-- FIXED
        return ResponseEntity.ok(ApiResponse.success(userDto));
    }
}
