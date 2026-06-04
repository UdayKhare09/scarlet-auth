package org.teamzemo.scarletauth.service;

import org.teamzemo.scarletauth.dto.*;
import org.teamzemo.scarletauth.entity.PasswordResetToken;
import org.teamzemo.scarletauth.entity.User;
import org.teamzemo.scarletauth.entity.UserPassword;
import org.teamzemo.scarletauth.repository.OAuth2AccountRepository;
import org.teamzemo.scarletauth.repository.PasskeyCredentialRepository;
import org.teamzemo.scarletauth.repository.PasswordResetTokenRepository;
import org.teamzemo.scarletauth.repository.UserPasswordRepository;
import org.teamzemo.scarletauth.entity.EmailVerificationToken;
import org.teamzemo.scarletauth.repository.EmailVerificationTokenRepository;
import org.teamzemo.scarletauth.repository.UserRepository;
import org.teamzemo.scarletauth.security.CookieUtils;
import org.teamzemo.scarletauth.security.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final UserPasswordRepository userPasswordRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final MfaService mfaService;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final CookieUtils cookieUtils;
    private final AuthenticationManager authenticationManager;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("An account with this email already exists");
        }

        User user = User.builder()
                .email(request.getEmail())
                .fullName(request.getFullName())
                .role("ROLE_USER")
                .build();
        user = userRepository.save(user);

        UserPassword userPassword = UserPassword.builder()
                .user(user)
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .build();
        userPasswordRepository.save(userPassword);

        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                .token(java.util.UUID.randomUUID().toString())
                .user(user)
                .expiryDate(java.time.Instant.now().plusSeconds(24 * 60 * 60)) // 24 hours
                .build();
        emailVerificationTokenRepository.save(verificationToken);

        emailService.sendVerificationEmail(user.getEmail(), verificationToken.getToken());

        log.info("User registered, pending verification: {}", user.getEmail());

        return AuthResponse.builder()
                .message("Registration successful. Please check your email to verify your account.")
                .user(toUserResponse(user))
                .build();
    }

    public AuthResponse login(LoginRequest request, HttpServletResponse response) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.isEmailVerified()) {
            throw new RuntimeException("Email not verified. Please check your inbox.");
        }

        AuthResponse mfaChallenge = mfaService.buildMfaChallenge(user);
        if (mfaChallenge != null) {
            return mfaChallenge;
        }

        String accessToken = jwtService.generateAccessToken(user.getEmail(), user.getId(), user.getFullName());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail(), user.getId());

        cookieUtils.setAccessTokenCookie(response, accessToken);
        cookieUtils.setRefreshTokenCookie(response, refreshToken);

        log.info("User logged in: {}", user.getEmail());

        return AuthResponse.builder()
                .message("Login successful")
                .user(toUserResponse(user))
                .build();
    }

    public void logout(HttpServletResponse response) {
        cookieUtils.clearAuthCookies(response);
    }

    public AuthResponse refresh(String refreshToken, HttpServletResponse response) {
        if (!jwtService.isTokenValid(refreshToken)) {
            throw new RuntimeException("Invalid or expired refresh token");
        }

        String tokenType = jwtService.extractTokenType(refreshToken);
        if (!"refresh".equals(tokenType)) {
            throw new RuntimeException("Invalid token type");
        }

        String email = jwtService.extractEmail(refreshToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String newAccessToken = jwtService.generateAccessToken(user.getEmail(), user.getId(), user.getFullName());
        cookieUtils.setAccessTokenCookie(response, newAccessToken);

        log.info("Token refreshed for user: {}", email);

        return AuthResponse.builder()
                .message("Token refreshed")
                .user(toUserResponse(user))
                .build();
    }

    @Transactional
    public void verifyEmail(String tokenStr) {
        EmailVerificationToken token = emailVerificationTokenRepository.findByToken(tokenStr)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));

        if (token.isExpired()) {
            emailVerificationTokenRepository.delete(token);
            throw new RuntimeException("Verification token has expired. Please register again.");
        }

        User user = token.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        emailVerificationTokenRepository.delete(token);
        log.info("Email verified for user: {}", user.getEmail());
    }

    @Transactional
    public void forgotPassword(String email) {
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            log.info("Password reset requested for non-existent email: {}", email);
            return;
        }

        passwordResetTokenRepository.deleteByUser(user);

        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(java.util.UUID.randomUUID().toString())
                .user(user)
                .expiryDate(java.time.Instant.now().plusSeconds(60 * 60)) // 1 hour
                .build();
        passwordResetTokenRepository.save(resetToken);

        emailService.sendPasswordResetEmail(user.getEmail(), resetToken.getToken());
        log.info("Password reset email sent to: {}", email);
    }

    @Transactional
    public void resetPassword(String tokenStr, String newPassword) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(tokenStr)
                .orElseThrow(() -> new RuntimeException("Invalid or expired password reset link"));

        if (resetToken.isExpired()) {
            passwordResetTokenRepository.delete(resetToken);
            throw new RuntimeException("Password reset link has expired. Please request a new one.");
        }

        User user = resetToken.getUser();

        UserPassword userPassword = userPasswordRepository.findByUser(user)
                .orElseGet(() -> UserPassword.builder().user(user).passwordHash("").build());
        userPassword.setPasswordHash(passwordEncoder.encode(newPassword));
        userPasswordRepository.save(userPassword);

        if (!user.isEmailVerified()) {
            user.setEmailVerified(true);
            userRepository.save(user);
        }

        passwordResetTokenRepository.delete(resetToken);
        log.info("Password reset successful for user: {}", user.getEmail());
    }

    @Transactional(readOnly = true)
    public UserResponse getCurrentUser(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return toUserResponse(user);
    }

    private UserResponse toUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .role(user.getRole())
                .createdAt(user.getCreatedAt())
                .hasPassword(userPasswordRepository.existsByUser_Id(user.getId()))
                .hasPasskey(passkeyCredentialRepository.existsByUser_Id(user.getId()))
                .hasOAuth2(oAuth2AccountRepository.existsByUser_Id(user.getId()))
                .build();
    }

    @Transactional
    public void changePassword(String email, String currentPassword, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        UserPassword userPassword = userPasswordRepository.findByUser(user).orElse(null);

        if (userPassword != null) {
            if (currentPassword == null || !passwordEncoder.matches(currentPassword, userPassword.getPasswordHash())) {
                throw new RuntimeException("Current password is incorrect");
            }
            if (passwordEncoder.matches(newPassword, userPassword.getPasswordHash())) {
                throw new RuntimeException("New password must be different from your current password");
            }
            userPassword.setPasswordHash(passwordEncoder.encode(newPassword));
        } else {
            userPassword = UserPassword.builder()
                    .user(user)
                    .passwordHash(passwordEncoder.encode(newPassword))
                    .build();
        }

        userPasswordRepository.save(userPassword);
        log.info("Password changed for user: {}", email);
    }
}
