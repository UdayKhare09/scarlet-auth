package org.teamzemo.scarletauth.entity;

import lombok.*;
import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSession {
    private UUID id; // JWT JTI
    private UUID userId;
    private String userEmail;
    private String ipAddress;
    private String deviceDetails;
    private String browser;
    private String os;
    private Instant createdAt;
    private Instant lastActiveAt;
    private Instant expiryDate;
}
