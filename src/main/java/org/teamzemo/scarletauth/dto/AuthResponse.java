package org.teamzemo.scarletauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String message;
    private UserResponse user;
    private boolean mfaRequired;
    private String pendingToken;
    private List<String> availableMfaMethods;
}
