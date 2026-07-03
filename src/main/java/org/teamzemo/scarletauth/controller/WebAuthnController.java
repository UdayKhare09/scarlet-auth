package org.teamzemo.scarletauth.controller;

import org.teamzemo.scarletauth.dto.WebAuthnAuthenticationRequest;
import org.teamzemo.scarletauth.dto.WebAuthnRegistrationRequest;
import org.teamzemo.scarletauth.entity.User;
import org.teamzemo.scarletauth.security.CookieUtils;
import org.teamzemo.scarletauth.security.JwtService;
import org.teamzemo.scarletauth.service.WebAuthnService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/webauthn")
@RequiredArgsConstructor
public class WebAuthnController {

    private final WebAuthnService webAuthnService;
    private final JwtService jwtService;
    private final CookieUtils cookieUtils;
    private final org.teamzemo.scarletauth.service.SessionService sessionService;

    @GetMapping("/register/options")
    public ResponseEntity<Map<String, Object>> getRegistrationOptions(
            @AuthenticationPrincipal UserDetails userDetails) {
        Map<String, Object> options = webAuthnService.generateRegistrationOptions(userDetails.getUsername());
        return ResponseEntity.ok(options);
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> verifyRegistration(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody WebAuthnRegistrationRequest request) {
        webAuthnService.verifyRegistration(
                userDetails.getUsername(),
                request.getCredentialId(),
                request.getAttestationObject(),
                request.getClientDataJSON(),
                request.getLabel(),
                request.getTransports()
        );
        return ResponseEntity.ok(Map.of("message", "Passkey registered successfully"));
    }

    @GetMapping("/authenticate/options")
    public ResponseEntity<Map<String, Object>> getAuthenticationOptions(
            @RequestParam(required = false) String email) {
        Map<String, Object> options = webAuthnService.generateAuthenticationOptions(email);
        return ResponseEntity.ok(options);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<Map<String, Object>> verifyAuthentication(
            @RequestBody WebAuthnAuthenticationRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        User user = webAuthnService.verifyAuthentication(
                request.getCredentialId(),
                request.getAuthenticatorData(),
                request.getClientDataJSON(),
                request.getSignature(),
                request.getUserHandle()
        );

        String accessToken = jwtService.generateAccessToken(user.getEmail(), user.getId(), user.getFirstName(), user.getLastName(), user.getRole());
        sessionService.createSession(user, httpRequest, response);
        cookieUtils.setAccessTokenCookie(response, accessToken);

        return ResponseEntity.ok(Map.of(
                "message", "Authentication successful",
                "email", user.getEmail()
        ));
    }

    @GetMapping("/passkeys")
    public ResponseEntity<List<Map<String, Object>>> listPasskeys(
            @AuthenticationPrincipal UserDetails userDetails) {
        List<Map<String, Object>> passkeys = webAuthnService.listPasskeys(userDetails.getUsername());
        return ResponseEntity.ok(passkeys);
    }

    @DeleteMapping("/passkeys/{credentialId}")
    public ResponseEntity<Map<String, Object>> deletePasskey(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable String credentialId) {
        webAuthnService.deletePasskey(userDetails.getUsername(), credentialId);
        return ResponseEntity.ok(Map.of("message", "Passkey deleted"));
    }
}
