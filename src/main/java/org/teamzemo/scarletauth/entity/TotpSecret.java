package org.teamzemo.scarletauth.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "auth_totp_secrets")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class TotpSecret {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(nullable = false)
    private String secret;

    @Builder.Default
    private boolean confirmed = false;
}
