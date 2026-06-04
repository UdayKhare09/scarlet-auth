package org.teamzemo.scarletauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WebAuthnRegistrationRequest {
    private String credentialId;
    private String attestationObject;
    private String clientDataJSON;
    private String label;
    private String transports;
}
