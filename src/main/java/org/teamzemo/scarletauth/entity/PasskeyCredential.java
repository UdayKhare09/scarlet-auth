package org.teamzemo.scarletauth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_passkey_credentials")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class PasskeyCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "credential_id", nullable = false, unique = true, length = 1024)
    private String credentialId;

    @Column(name = "public_key_cose", nullable = false, columnDefinition = "TEXT")
    private String publicKeyCose; // Base64-encoded COSE public key

    @Column(name = "sign_count", nullable = false)
    @Builder.Default
    private long signCount = 0;

    @Column(length = 256)
    private String label; // human-readable name e.g. "MacBook Touch ID"

    @Column(length = 512)
    private String transports; // comma-separated: "internal,hybrid"

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;
}
