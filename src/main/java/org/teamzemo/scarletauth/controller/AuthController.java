package org.teamzemo.scarletauth.controller;

import org.teamzemo.scarletauth.dto.*;
import org.teamzemo.scarletauth.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration request received for email: {}", request.getEmail());
        AuthResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<AuthResponse> verifyEmail(@RequestParam String token) {
        log.info("Email verification request received");
        authService.verifyEmail(token);
        return ResponseEntity.ok(
                AuthResponse.builder().message("Email verified successfully. You can now log in.").build()
        );
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletRequest httpRequest,
                                               HttpServletResponse response) {
        log.info("Login request received for email: {}", request.getEmail());
        AuthResponse authResponse = authService.login(request, httpRequest, response);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<AuthResponse> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(request, response);
        return ResponseEntity.ok(
                AuthResponse.builder().message("Logged out successfully").build()
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(HttpServletRequest request,
                                                 HttpServletResponse response) {
        String refreshToken = null;
        if (request.getCookies() != null) {
            refreshToken = Arrays.stream(request.getCookies())
                    .filter(c -> "refresh_token".equals(c.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }

        if (refreshToken == null) {
            return ResponseEntity.status(401).body(
                    AuthResponse.builder().message("No refresh token found").build()
            );
        }

        AuthResponse authResponse = authService.refresh(refreshToken, request, response);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<AuthResponse> forgotPassword(@RequestParam String email) {
        authService.forgotPassword(email);
        return ResponseEntity.ok(
                AuthResponse.builder()
                        .message("If an account with that email exists, a password reset link has been sent.")
                        .build()
        );
    }

    @PostMapping("/reset-password")
    public ResponseEntity<AuthResponse> resetPassword(@RequestParam String token,
                                                       @RequestParam String newPassword) {
        if (newPassword == null || newPassword.length() < 8) {
            return ResponseEntity.badRequest().body(
                    AuthResponse.builder().message("Password must be at least 8 characters.").build()
            );
        }
        authService.resetPassword(token, newPassword);
        return ResponseEntity.ok(
                AuthResponse.builder().message("Password reset successful. You can now log in.").build()
        );
    }

    @PostMapping("/change-password")
    public ResponseEntity<AuthResponse> changePassword(
            @RequestBody ChangePasswordRequest request,
            java.security.Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(
                    AuthResponse.builder().message("Not authenticated").build()
            );
        }
        if (request.getNewPassword() == null || request.getNewPassword().length() < 8) {
            return ResponseEntity.badRequest().body(
                    AuthResponse.builder().message("Password must be at least 8 characters.").build()
            );
        }
        authService.changePassword(principal.getName(), request.getCurrentPassword(), request.getNewPassword());
        return ResponseEntity.ok(
                AuthResponse.builder().message("Password changed successfully.").build()
        );
    }

    @PostMapping("/google-login")
    public ResponseEntity<AuthResponse> googleLogin(
            @Valid @RequestBody GoogleLoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        AuthResponse authResponse = authService.googleLogin(request.getIdToken(), httpRequest, response);
        return ResponseEntity.ok(authResponse);
    }
}
