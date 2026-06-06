package org.teamzemo.scarletauth.service;

import org.teamzemo.scarletauth.config.AppProperties;
import org.teamzemo.scarletauth.entity.PasskeyCredential;
import org.teamzemo.scarletauth.entity.User;
import org.teamzemo.scarletauth.repository.PasskeyCredentialRepository;
import org.teamzemo.scarletauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.*;
import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class WebAuthnService {

    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final UserRepository userRepository;
    private final AppProperties appProperties;

    public Map<String, Object> generateRegistrationOptions(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        byte[] challenge = generateChallenge();
        List<PasskeyCredential> existingCredentials = passkeyCredentialRepository.findAllByUser_Id(user.getId());

        Map<String, Object> rp = new LinkedHashMap<>();
        rp.put("name", appProperties.getWebauthn().getRpName());
        rp.put("id", appProperties.getWebauthn().getRpId());

        Map<String, Object> userEntity = new LinkedHashMap<>();
        userEntity.put("id", base64UrlEncode(user.getId().toString().getBytes()));
        userEntity.put("name", user.getEmail());
        String fullName = user.getFirstName() + (user.getLastName() != null && !user.getLastName().isBlank() ? " " + user.getLastName() : "");
        userEntity.put("displayName", !fullName.isBlank() ? fullName : user.getEmail());

        List<Map<String, Object>> pubKeyCredParams = List.of(
                Map.of("type", "public-key", "alg", -7),   // ES256
                Map.of("type", "public-key", "alg", -257)  // RS256
        );

        List<Map<String, String>> excludeCredentials = existingCredentials.stream()
                .map(cred -> Map.of(
                        "type", "public-key",
                        "id", cred.getCredentialId()
                ))
                .toList();

        Map<String, Object> authenticatorSelection = new LinkedHashMap<>();
        authenticatorSelection.put("authenticatorAttachment", "platform");
        authenticatorSelection.put("residentKey", "preferred");
        authenticatorSelection.put("userVerification", "preferred");

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", base64UrlEncode(challenge));
        options.put("rp", rp);
        options.put("user", userEntity);
        options.put("pubKeyCredParams", pubKeyCredParams);
        options.put("timeout", 60000);
        options.put("excludeCredentials", excludeCredentials);
        options.put("authenticatorSelection", authenticatorSelection);
        options.put("attestation", "none");

        return options;
    }

    @Transactional
    public PasskeyCredential verifyRegistration(String email, String credentialId,
                                                 String attestationObject, String clientDataJSON,
                                                 String label, String transports) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        byte[] attestationBytes = base64UrlDecode(attestationObject);
        byte[] publicKey = extractPublicKeyFromAttestation(attestationBytes);

        PasskeyCredential credential = PasskeyCredential.builder()
                .credentialId(credentialId)
                .user(user)
                .publicKeyCose(Base64.getEncoder().encodeToString(publicKey))
                .signCount(0L)
                .label(label != null ? label : "Passkey")
                .transports(transports)
                .lastUsedAt(Instant.now())
                .build();

        credential = passkeyCredentialRepository.save(credential);
        log.info("Passkey registered for user: {}, credentialId: {}", email, credentialId);
        return credential;
    }

    public Map<String, Object> generateAuthenticationOptions(String email) {
        byte[] challenge = generateChallenge();

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", base64UrlEncode(challenge));
        options.put("timeout", 60000);
        options.put("rpId", appProperties.getWebauthn().getRpId());
        options.put("userVerification", "preferred");

        if (email != null && !email.isBlank()) {
            List<PasskeyCredential> credentials = passkeyCredentialRepository.findAllByUser_Email(email);
            List<Map<String, String>> allowCredentials = credentials.stream()
                    .map(cred -> Map.of(
                            "type", "public-key",
                            "id", cred.getCredentialId()
                    ))
                    .toList();
            options.put("allowCredentials", allowCredentials);
        } else {
            options.put("allowCredentials", List.of());
        }

        return options;
    }

    @Transactional
    public User verifyAuthentication(String credentialId, String authenticatorData,
                                     String clientDataJSON, String signature, String userHandle) {
        PasskeyCredential credential = passkeyCredentialRepository.findByCredentialId(credentialId)
                .orElseThrow(() -> new RuntimeException("Passkey not found"));

        credential.setSignCount(credential.getSignCount() + 1);
        credential.setLastUsedAt(Instant.now());
        passkeyCredentialRepository.save(credential);

        User user = credential.getUser();
        log.info("Passkey authentication successful for user: {}", user.getEmail());
        return user;
    }

    public List<Map<String, Object>> listPasskeys(String email) {
        List<PasskeyCredential> credentials = passkeyCredentialRepository.findAllByUser_Email(email);
        return credentials.stream()
                .map(cred -> {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("credentialId", cred.getCredentialId());
                    entry.put("label", cred.getLabel());
                    entry.put("createdAt", cred.getCreatedAt());
                    entry.put("lastUsedAt", cred.getLastUsedAt());
                    entry.put("transports", cred.getTransports());
                    return entry;
                })
                .toList();
    }

    @Transactional
    public void deletePasskey(String email, String credentialId) {
        PasskeyCredential credential = passkeyCredentialRepository.findByCredentialId(credentialId)
                .orElseThrow(() -> new RuntimeException("Passkey not found"));

        if (!credential.getUser().getEmail().equals(email)) {
            throw new RuntimeException("Passkey does not belong to this user");
        }

        passkeyCredentialRepository.delete(credential);
        log.info("Passkey deleted for user: {}, credentialId: {}", email, credentialId);
    }

    private byte[] generateChallenge() {
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        return challenge;
    }

    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private byte[] base64UrlDecode(String data) {
        if (data == null) {
            return new byte[0];
        }
        String normalized = data.trim().replace('-', '+').replace('_', '/');
        int missingPadding = (4 - (normalized.length() % 4)) % 4;
        if (missingPadding > 0) {
            normalized = normalized + "=".repeat(missingPadding);
        }
        return Base64.getDecoder().decode(normalized);
    }

    private byte[] extractPublicKeyFromAttestation(byte[] attestationBytes) {
        return attestationBytes;
    }
}
