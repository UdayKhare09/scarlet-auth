package org.teamzemo.scarletauth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username:noreply@scarlet.com}")
    private String fromEmail;

    @Value("${app.frontend-url:http://localhost}")
    private String frontendUrl;

    public void sendVerificationEmail(String toEmail, String token) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("Verify your Scarlet account");

            String verificationUrl = frontendUrl + "/verify-email?token=" + token;
            
            message.setText("Welcome to Scarlet!\n\n" +
                    "Please click the link below to verify your email address and activate your account:\n\n" +
                    verificationUrl + "\n\n" +
                    "This link will expire in 24 hours.\n\n" +
                    "If you did not create an account, please ignore this email.");

            mailSender.send(message);
            log.info("Verification email sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send verification email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send verification email. Please try again later.");
        }
    }

    public void sendPasswordResetEmail(String toEmail, String token) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("Reset your Scarlet password");

            String resetUrl = frontendUrl + "/reset-password?token=" + token;

            message.setText("Hello,\n\n" +
                    "We received a request to reset the password for your Scarlet account.\n\n" +
                    "Click the link below to reset your password:\n\n" +
                    resetUrl + "\n\n" +
                    "This link will expire in 1 hour.\n\n" +
                    "If you did not request a password reset, please ignore this email — your password will remain unchanged.");

            mailSender.send(message);
            log.info("Password reset email sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send password reset email. Please try again later.");
        }
    }

    public void sendMfaOtpEmail(String toEmail, String otpCode) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("Your Scarlet login code: " + otpCode);

            message.setText("Your one-time login code is:\n\n" +
                    "  " + otpCode + "\n\n" +
                    "This code expires in 10 minutes.\n\n" +
                    "If you did not request this code, please ignore this email and secure your account.");

            mailSender.send(message);
            log.info("MFA OTP email sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send MFA OTP email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send login code. Please try again later.");
        }
    }
}
