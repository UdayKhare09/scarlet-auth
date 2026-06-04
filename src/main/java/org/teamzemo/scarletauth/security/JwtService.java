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

    public String generateAccessToken(String email, UUID userId, String fullName) {
        return buildToken(email, userId, fullName, accessTokenExpirationMs, "access");
    }

    public String generateRefreshToken(String email, UUID userId) {
        return buildToken(email, userId, null, refreshTokenExpirationMs, "refresh");
    }

    public String generateAccessToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return generateAccessToken(userDetails.getUsername(), null, null);
    }

    private String buildToken(String subject, UUID userId, String fullName, long expirationMs, String tokenType) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        var builder = Jwts.builder()
                .subject(subject)
                .issuedAt(now)
                .expiration(expiry)
                .claim("type", tokenType);

        if (userId != null) {
            builder.claim("userId", userId.toString());
        }

        if (fullName != null) {
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
