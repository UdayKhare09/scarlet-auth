package org.teamzemo.scarletauth.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "auth_mfa_settings")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class MfaSettings {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Builder.Default
    @Column(name = "totp_enabled")
    private boolean totpEnabled = false;

    @Builder.Default
    @Column(name = "email_otp_enabled")
    private boolean emailOtpEnabled = false;
}
