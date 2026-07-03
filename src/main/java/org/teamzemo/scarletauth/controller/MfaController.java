package org.teamzemo.scarletauth.controller;

import org.teamzemo.scarletauth.dto.*;
import org.teamzemo.scarletauth.service.MfaService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final MfaService mfaService;

    @GetMapping("/status")
    public ResponseEntity<MfaStatusResponse> getStatus(Principal principal) {
        return ResponseEntity.ok(mfaService.getMfaStatus(principal.getName()));
    }

    @PostMapping("/email-otp/enable")
    public ResponseEntity<AuthResponse> enableEmailOtp(Principal principal) {
        mfaService.setEmailOtp(principal.getName(), true);
        return ResponseEntity.ok(AuthResponse.builder().message("Email OTP enabled.").build());
    }

    @PostMapping("/email-otp/disable")
    public ResponseEntity<AuthResponse> disableEmailOtp(Principal principal) {
        mfaService.setEmailOtp(principal.getName(), false);
        return ResponseEntity.ok(AuthResponse.builder().message("Email OTP disabled.").build());
    }

    @PostMapping("/totp/setup")
    public ResponseEntity<TotpSetupResponse> setupTotp(Principal principal) {
        return ResponseEntity.ok(mfaService.initiateTotpSetup(principal.getName()));
    }

    @PostMapping("/totp/confirm")
    public ResponseEntity<AuthResponse> confirmTotp(Principal principal,
                                                     @RequestParam int code) {
        mfaService.confirmTotpSetup(principal.getName(), code);
        return ResponseEntity.ok(AuthResponse.builder().message("Authenticator app connected successfully.").build());
    }

    @PostMapping("/totp/disable")
    public ResponseEntity<AuthResponse> disableTotp(Principal principal) {
        mfaService.disableTotp(principal.getName());
        return ResponseEntity.ok(AuthResponse.builder().message("TOTP disabled.").build());
    }

    @PostMapping("/send-email-otp")
    public ResponseEntity<AuthResponse> sendEmailOtp(@RequestParam String pendingToken) {
        mfaService.sendEmailOtp(pendingToken);
        return ResponseEntity.ok(AuthResponse.builder().message("Code sent to your email.").build());
    }

    @PostMapping("/complete")
    public ResponseEntity<AuthResponse> completeMfa(@RequestBody CompleteMfaRequest request,
                                                     jakarta.servlet.http.HttpServletRequest httpRequest,
                                                     HttpServletResponse response) {
        AuthResponse authResponse = mfaService.completeMfaChallenge(request, httpRequest, response);
        return ResponseEntity.ok(authResponse);
    }
}
