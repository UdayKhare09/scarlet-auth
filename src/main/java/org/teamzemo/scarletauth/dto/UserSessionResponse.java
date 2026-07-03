package org.teamzemo.scarletauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSessionResponse {
    private UUID id;
    private String ipAddress;
    private String deviceDetails;
    private String browser;
    private String os;
    private Instant createdAt;
    private Instant lastActiveAt;
    private boolean current;
}
