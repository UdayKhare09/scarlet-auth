package org.teamzemo.scarletauth.dto;

import java.util.UUID;

public record UserSyncRequest(
    UUID id,
    String email,
    String firstName,
    String lastName
) {}
