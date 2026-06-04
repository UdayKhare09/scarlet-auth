package org.teamzemo.scarletauth.dto;

import lombok.Data;

@Data
public class CompleteMfaRequest {
    private String pendingToken;
    private String method;
    private String code;
}
