package org.teamzemo.scarletauth.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "auth_user_passwords")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class UserPassword {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;
}
