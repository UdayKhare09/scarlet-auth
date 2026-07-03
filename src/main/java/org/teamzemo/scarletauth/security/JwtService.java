package org.teamzemo.scarletauth.security;

import org.teamzemo.scarletauth.config.AppProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;
import java.util.function.Function;

@Service
@Slf4j
public class JwtService {

    private final SecretKey signingKey;
    private final long accessTokenExpirationMs;
    private final long refreshTokenExpirationMs;

    public JwtService(AppProperties appProperties) {
        byte[] keyBytes = Decoders.BASE64.decode(appProperties.getJwt().getSecret());
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenExpirationMs = appProperties.getJwt().getAccessTokenExpirationMs();
        this.refreshTokenExpirationMs = appProperties.getJwt().getRefreshTokenExpirationMs();
    }

    public String generateAccessToken(String email, UUID userId, String firstName, String lastName, String role) {
        return buildToken(email, userId, firstName, lastName, role, accessTokenExpirationMs, "access");
    }

    public String generateRefreshToken(String email, UUID userId) {
        return generateRefreshToken(email, userId, UUID.randomUUID().toString());
    }

    public String generateRefreshToken(String email, UUID userId, String jti) {
        return buildToken(email, userId, null, null, null, refreshTokenExpirationMs, "refresh", jti);
    }

    public String generateAccessToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String role = userDetails.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .findFirst()
                .orElse("ROLE_USER");
        return generateAccessToken(userDetails.getUsername(), null, null, null, role);
    }

    private String buildToken(String subject, UUID userId, String firstName, String lastName, String role, long expirationMs, String tokenType) {
        return buildToken(subject, userId, firstName, lastName, role, expirationMs, tokenType, null);
    }

    private String buildToken(String subject, UUID userId, String firstName, String lastName, String role, long expirationMs, String tokenType, String jti) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        var builder = Jwts.builder()
                .subject(subject)
                .issuedAt(now)
                .expiration(expiry)
                .claim("type", tokenType);

        if (jti != null) {
            builder.id(jti);
        }

        if (userId != null) {
            builder.claim("userId", userId.toString());
        }

        if (firstName != null) {
            builder.claim("firstName", firstName);
        }

        if (lastName != null) {
            builder.claim("lastName", lastName);
        }

        if (role != null) {
            builder.claim("role", role);
        }

        if (firstName != null) {
            String fullName = firstName + (lastName != null && !lastName.isBlank() ? " " + lastName : "");
            builder.claim("fullName", fullName);
        }

        return builder.signWith(signingKey).compact();
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get("type", String.class));
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    public boolean isTokenValid(String token) {
        try {
            Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String email = extractEmail(token);
        return email.equals(userDetails.getUsername()) && isTokenValid(token);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claimsResolver.apply(claims);
    }
}
