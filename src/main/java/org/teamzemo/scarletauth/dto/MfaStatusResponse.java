package org.teamzemo.scarletauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MfaStatusResponse {
    private boolean emailOtpEnabled;
    private boolean totpEnabled;
    private boolean totpConfirmed;
}
