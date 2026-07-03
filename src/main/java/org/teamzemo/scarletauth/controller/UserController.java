package org.teamzemo.scarletauth.controller;

import org.teamzemo.scarletauth.dto.UserResponse;
import org.teamzemo.scarletauth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserController {

    private final AuthService authService;

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(401).body("Not authenticated");
        }
        UserResponse user = authService.getCurrentUser(userDetails.getUsername());
        return ResponseEntity.ok(user);
    }

    @PostMapping("/internal/sync-profile")
    public ResponseEntity<?> syncProfile(
            @RequestParam("userId") java.util.UUID userId,
            @RequestParam("firstName") String firstName,
            @RequestParam("lastName") String lastName) {
        authService.syncProfile(userId, firstName, lastName);
        return ResponseEntity.ok().build();
    }
}
