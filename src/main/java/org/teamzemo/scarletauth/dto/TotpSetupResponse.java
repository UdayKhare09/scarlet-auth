package org.teamzemo.scarletauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TotpSetupResponse {
    private String secret;
    private String otpauthUrl;
    private String qrCodeBase64;
}
