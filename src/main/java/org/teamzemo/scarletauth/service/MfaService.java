package org.teamzemo.scarletauth.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.teamzemo.scarletauth.dto.*;
import org.teamzemo.scarletauth.entity.*;
import org.teamzemo.scarletauth.repository.*;
import org.teamzemo.scarletauth.security.CookieUtils;
import org.teamzemo.scarletauth.security.JwtService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class MfaService {

    private final MfaSettingsRepository mfaSettingsRepository;
    private final TotpSecretRepository totpSecretRepository;
    private final EmailOtpRepository emailOtpRepository;
    private final PendingMfaTokenRepository pendingMfaTokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final JwtService jwtService;
    private final CookieUtils cookieUtils;

    private static final String ALPHANUMERIC = "ABCDEFGHJKLMNPQRSTUVWXY3456789";
    private static final SecureRandom secureRandom = new SecureRandom();

    @Transactional(readOnly = true)
    public MfaStatusResponse getMfaStatus(String email) {
        User user = getUser(email);
        MfaSettings settings = mfaSettingsRepository.findByUser(user)
                .orElse(MfaSettings.builder().user(user).build());
        TotpSecret totpSecret = totpSecretRepository.findByUser(user).orElse(null);

        return MfaStatusResponse.builder()
                .emailOtpEnabled(settings.isEmailOtpEnabled())
                .totpEnabled(settings.isTotpEnabled())
                .totpConfirmed(totpSecret != null && totpSecret.isConfirmed())
                .build();
    }

    @Transactional
    public void setEmailOtp(String email, boolean enabled) {
        User user = getUser(email);
        MfaSettings settings = getOrCreateSettings(user);
        settings.setEmailOtpEnabled(enabled);
        mfaSettingsRepository.save(settings);
        log.info("Email OTP {} for user: {}", enabled ? "enabled" : "disabled", email);
    }

    @Transactional
    public TotpSetupResponse initiateTotpSetup(String email) {
        User user = getUser(email);
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        GoogleAuthenticatorKey credentials = gAuth.createCredentials();
        String secret = credentials.getKey();

        TotpSecret totpSecret = totpSecretRepository.findByUser(user)
                .orElse(TotpSecret.builder().user(user).build());
        totpSecret.setSecret(secret);
        totpSecret.setConfirmed(false);
        totpSecretRepository.save(totpSecret);

        String issuer = "Scarlet";
        String otpauthUrl = GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(issuer, user.getEmail(), credentials);
        String qrBase64 = generateQrCodeBase64(otpauthUrl);

        return TotpSetupResponse.builder()
                .secret(secret)
                .otpauthUrl(otpauthUrl)
                .qrCodeBase64(qrBase64)
                .build();
    }

    @Transactional
    public void confirmTotpSetup(String email, int code) {
        User user = getUser(email);
        TotpSecret totpSecret = totpSecretRepository.findByUser(user)
                .orElseThrow(() -> new RuntimeException("TOTP setup not started. Please scan QR code first."));

        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        boolean valid = gAuth.authorize(totpSecret.getSecret(), code);
        if (!valid) {
            throw new RuntimeException("Invalid code. Please check your authenticator app and try again.");
        }

        totpSecret.setConfirmed(true);
        totpSecretRepository.save(totpSecret);

        MfaSettings settings = getOrCreateSettings(user);
        settings.setTotpEnabled(true);
        mfaSettingsRepository.save(settings);

        log.info("TOTP confirmed and enabled for user: {}", email);
    }

    @Transactional
    public void disableTotp(String email) {
        User user = getUser(email);
        totpSecretRepository.deleteByUser(user);
        MfaSettings settings = getOrCreateSettings(user);
        settings.setTotpEnabled(false);
        mfaSettingsRepository.save(settings);
        log.info("TOTP disabled for user: {}", email);
    }

    @Transactional
    public AuthResponse buildMfaChallenge(User user) {
        MfaSettings settings = mfaSettingsRepository.findByUser(user).orElse(null);
        if (settings == null || (!settings.isEmailOtpEnabled() && !settings.isTotpEnabled())) {
            return null;
        }

        List<String> methods = new ArrayList<>();
        if (settings.isEmailOtpEnabled()) methods.add("email_otp");
        if (settings.isTotpEnabled()) methods.add("totp");

        pendingMfaTokenRepository.findAll().stream()
                .filter(t -> t.getUser().getId().equals(user.getId()))
                .forEach(pendingMfaTokenRepository::delete);

        PendingMfaToken pending = PendingMfaToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiryDate(Instant.now().plusSeconds(10 * 60))
                .build();
        pendingMfaTokenRepository.save(pending);

        return AuthResponse.builder()
                .mfaRequired(true)
                .pendingToken(pending.getToken())
                .availableMfaMethods(methods)
                .message("MFA verification required")
                .build();
    }

    @Transactional
    public void sendEmailOtp(String pendingToken) {
        PendingMfaToken pending = resolvePendingToken(pendingToken);
        User user = pending.getUser();

        emailOtpRepository.deleteByUser(user);

        String otp = generateAlphanumericOtp(6);
        EmailOtp emailOtp = EmailOtp.builder()
                .user(user)
                .otpCode(otp)
                .purpose("mfa_login")
                .expiryDate(Instant.now().plusSeconds(10 * 60))
                .build();
        emailOtpRepository.save(emailOtp);
        emailService.sendMfaOtpEmail(user.getEmail(), otp);
        log.info("Email OTP sent for MFA to: {}", user.getEmail());
    }

    @Transactional
    public AuthResponse completeMfaChallenge(CompleteMfaRequest request, HttpServletResponse response) {
        PendingMfaToken pending = resolvePendingToken(request.getPendingToken());
        User user = pending.getUser();

        switch (request.getMethod()) {
            case "email_otp" -> verifyEmailOtp(user, request.getCode());
            case "totp" -> verifyTotp(user, request.getCode());
            default -> throw new RuntimeException("Unknown MFA method: " + request.getMethod());
        }

        pendingMfaTokenRepository.delete(pending);

        String accessToken = jwtService.generateAccessToken(user.getEmail(), user.getId(), user.getFullName());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail(), user.getId());
        cookieUtils.setAccessTokenCookie(response, accessToken);
        cookieUtils.setRefreshTokenCookie(response, refreshToken);

        log.info("MFA completed via {} for user: {}", request.getMethod(), user.getEmail());
        return AuthResponse.builder().message("Login successful").build();
    }

    private void verifyEmailOtp(User user, String code) {
        EmailOtp otp = emailOtpRepository
                .findTopByUserAndPurposeOrderByExpiryDateDesc(user, "mfa_login")
                .orElseThrow(() -> new RuntimeException("No OTP found. Please request a new code."));

        if (otp.isExpired()) {
            emailOtpRepository.delete(otp);
            throw new RuntimeException("OTP has expired. Please request a new code.");
        }
        if (!otp.getOtpCode().equalsIgnoreCase(code)) {
            throw new RuntimeException("Invalid OTP code.");
        }
        emailOtpRepository.delete(otp);
    }

    private void verifyTotp(User user, String code) {
        TotpSecret totpSecret = totpSecretRepository.findByUser(user)
                .orElseThrow(() -> new RuntimeException("TOTP not configured for this account."));
        if (!totpSecret.isConfirmed()) {
            throw new RuntimeException("TOTP setup not completed.");
        }

        int intCode;
        try {
            intCode = Integer.parseInt(code.trim());
        } catch (NumberFormatException e) {
            throw new RuntimeException("Invalid TOTP code format.");
        }

        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        if (!gAuth.authorize(totpSecret.getSecret(), intCode)) {
            throw new RuntimeException("Invalid TOTP code. Please check your authenticator app.");
        }
    }

    private PendingMfaToken resolvePendingToken(String token) {
        PendingMfaToken pending = pendingMfaTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid or expired MFA session. Please log in again."));
        if (pending.isExpired()) {
            pendingMfaTokenRepository.delete(pending);
            throw new RuntimeException("MFA session expired. Please log in again.");
        }
        return pending;
    }

    private String generateAlphanumericOtp(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(ALPHANUMERIC.charAt(secureRandom.nextInt(ALPHANUMERIC.length())));
        }
        return sb.toString();
    }

    private String generateQrCodeBase64(String content) {
        try {
            QRCodeWriter writer = new QRCodeWriter();
            BitMatrix matrix = writer.encode(content, BarcodeFormat.QR_CODE, 256, 256);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", out);
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(out.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate QR code.");
        }
    }

    private User getUser(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    private MfaSettings getOrCreateSettings(User user) {
        return mfaSettingsRepository.findByUser(user)
                .orElse(MfaSettings.builder().user(user).build());
    }

    public boolean isMfaEnabled(User user) {
        return mfaSettingsRepository.findByUser(user)
                .map(s -> s.isEmailOtpEnabled() || s.isTotpEnabled())
                .orElse(false);
    }
}
