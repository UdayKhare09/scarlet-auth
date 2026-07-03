package org.teamzemo.scarletauth.controller;

import org.teamzemo.scarletauth.dto.UserSessionResponse;
import org.teamzemo.scarletauth.entity.User;
import org.teamzemo.scarletauth.repository.UserRepository;
import org.teamzemo.scarletauth.security.JwtService;
import org.teamzemo.scarletauth.service.SessionService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class SessionController {

    private final SessionService sessionService;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    @GetMapping("/sessions")
    public ResponseEntity<List<UserSessionResponse>> getSessions(
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest request) {

        if (userDetails == null) {
            return ResponseEntity.status(401).build();
        }

        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        String refreshToken = null;
        if (request.getCookies() != null) {
            refreshToken = Arrays.stream(request.getCookies())
                    .filter(c -> "refresh_token".equals(c.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }

        String currentJti = null;
        if (refreshToken != null && jwtService.isTokenValid(refreshToken)) {
            currentJti = jwtService.extractJti(refreshToken);
        }

        List<UserSessionResponse> sessions = sessionService.getActiveSessions(user, currentJti);
        return ResponseEntity.ok(sessions);
    }

    @DeleteMapping("/sessions/{id}")
    public ResponseEntity<?> revokeSession(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable UUID id) {

        if (userDetails == null) {
            return ResponseEntity.status(401).build();
        }

        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        sessionService.revokeSession(id, user);
        return ResponseEntity.ok(Map.of("message", "Session revoked successfully"));
    }
}
