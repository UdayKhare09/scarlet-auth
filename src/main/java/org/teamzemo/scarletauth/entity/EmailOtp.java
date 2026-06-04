package org.teamzemo.scarletauth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "auth_email_otps")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class EmailOtp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "otp_code", nullable = false)
    private String otpCode;

    @Column(nullable = false)
    private String purpose; // "mfa_login", "mfa_setup"

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    public boolean isExpired() {
        return Instant.now().isAfter(expiryDate);
    }
}
