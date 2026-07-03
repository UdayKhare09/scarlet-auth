package org.teamzemo.scarletauth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.teamzemo.scarletauth.config.AppProperties;
import org.teamzemo.scarletauth.dto.UserSessionResponse;
import org.teamzemo.scarletauth.entity.User;
import org.teamzemo.scarletauth.entity.UserSession;
import org.teamzemo.scarletauth.security.CookieUtils;
import org.teamzemo.scarletauth.security.JwtService;
import org.teamzemo.scarletauth.security.UserAgentUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionService {

    private final StringRedisTemplate stringRedisTemplate;
    private final ObjectMapper objectMapper;
    private final JwtService jwtService;
    private final CookieUtils cookieUtils;
    private final AppProperties appProperties;

    private static final String SESSION_KEY_PREFIX = "session:";
    private static final String USER_SESSIONS_KEY_PREFIX = "user:sessions:";

    public String createSession(User user, HttpServletRequest request, HttpServletResponse response) {
        UUID jti = UUID.randomUUID();
        String userAgent = request.getHeader("User-Agent");
        System.out.println("USER-AGENT RECEIVED IN AUTH SERVICE: [" + userAgent + "]");
        String ipAddress = getClientIp(request);

        String browser = UserAgentUtils.parseBrowser(userAgent);
        String os = UserAgentUtils.parseOs(userAgent);
        String deviceDetails = UserAgentUtils.parseDevice(userAgent);

        Instant now = Instant.now();
        long expMs = appProperties.getJwt().getRefreshTokenExpirationMs();
        Instant expiry = now.plusMillis(expMs);

        UserSession session = UserSession.builder()
                .id(jti)
                .userId(user.getId())
                .userEmail(user.getEmail())
                .ipAddress(ipAddress)
                .deviceDetails(deviceDetails)
                .browser(browser)
                .os(os)
                .createdAt(now)
                .lastActiveAt(now)
                .expiryDate(expiry)
                .build();

        try {
            String json = objectMapper.writeValueAsString(session);
            // Store session key in Redis with native TTL
            stringRedisTemplate.opsForValue().set(
                    SESSION_KEY_PREFIX + jti, 
                    json, 
                    expMs, 
                    TimeUnit.MILLISECONDS
            );
            
            // Add session JTI to user's set of active sessions
            String userSessionsKey = USER_SESSIONS_KEY_PREFIX + user.getEmail();
            stringRedisTemplate.opsForSet().add(userSessionsKey, jti.toString());
            
            // Set TTL on the user sessions set to avoid orphan keys
            stringRedisTemplate.expire(userSessionsKey, expMs, TimeUnit.MILLISECONDS);
            
            log.info("Created active Redis session ID {} for user {}", jti, user.getEmail());
        } catch (Exception e) {
            log.error("Failed to serialize and store session in Redis", e);
            throw new RuntimeException("Session creation failed", e);
        }

        String refreshToken = jwtService.generateRefreshToken(user.getEmail(), user.getId(), jti.toString());
        cookieUtils.setRefreshTokenCookie(response, refreshToken);
        return refreshToken;
    }

    public List<UserSessionResponse> getActiveSessions(User user, String currentJti) {
        String userSessionsKey = USER_SESSIONS_KEY_PREFIX + user.getEmail();
        Set<String> jtis = stringRedisTemplate.opsForSet().members(userSessionsKey);
        
        if (jtis == null || jtis.isEmpty()) {
            return Collections.emptyList();
        }

        List<UserSession> activeSessions = new ArrayList<>();
        for (String jti : jtis) {
            String json = stringRedisTemplate.opsForValue().get(SESSION_KEY_PREFIX + jti);
            if (json == null) {
                // Lazily cleanup expired session from the user's set
                stringRedisTemplate.opsForSet().remove(userSessionsKey, jti);
            } else {
                try {
                    UserSession session = objectMapper.readValue(json, UserSession.class);
                    activeSessions.add(session);
                } catch (Exception e) {
                    log.error("Failed to deserialize session ID {}", jti, e);
                }
            }
        }

        return activeSessions.stream()
                .sorted(Comparator.comparing(UserSession::getLastActiveAt).reversed())
                .map(s -> UserSessionResponse.builder()
                        .id(s.getId())
                        .ipAddress(s.getIpAddress())
                        .deviceDetails(s.getDeviceDetails())
                        .browser(s.getBrowser())
                        .os(s.getOs())
                        .createdAt(s.getCreatedAt())
                        .lastActiveAt(s.getLastActiveAt())
                        .current(currentJti != null && currentJti.equals(s.getId().toString()))
                        .build())
                .collect(Collectors.toList());
    }

    public void revokeSession(UUID sessionId, User user) {
        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        String json = stringRedisTemplate.opsForValue().get(sessionKey);
        if (json != null) {
            try {
                UserSession session = objectMapper.readValue(json, UserSession.class);
                if (session.getUserId().equals(user.getId())) {
                    stringRedisTemplate.delete(sessionKey);
                    stringRedisTemplate.opsForSet().remove(USER_SESSIONS_KEY_PREFIX + session.getUserEmail(), sessionId.toString());
                    log.info("Revoked user session ID {} for user {}", sessionId, user.getEmail());
                }
            } catch (Exception e) {
                log.error("Failed to revoke session ID {}", sessionId, e);
            }
        }
    }

    public void revokeCurrentSession(String currentJti) {
        if (currentJti == null) return;
        String sessionKey = SESSION_KEY_PREFIX + currentJti;
        String json = stringRedisTemplate.opsForValue().get(sessionKey);
        if (json != null) {
            try {
                UserSession session = objectMapper.readValue(json, UserSession.class);
                stringRedisTemplate.delete(sessionKey);
                stringRedisTemplate.opsForSet().remove(USER_SESSIONS_KEY_PREFIX + session.getUserEmail(), currentJti);
                log.info("Revoked current session ID {}", currentJti);
            } catch (Exception e) {
                log.error("Failed to revoke current session ID {}", currentJti, e);
            }
        }
    }

    public boolean validateAndUpdateSession(String jti) {
        if (jti == null) return false;
        String sessionKey = SESSION_KEY_PREFIX + jti;
        String json = stringRedisTemplate.opsForValue().get(sessionKey);
        if (json == null) {
            return false;
        }

        try {
            UserSession session = objectMapper.readValue(json, UserSession.class);
            session.setLastActiveAt(Instant.now());

            Long ttl = stringRedisTemplate.getExpire(sessionKey, TimeUnit.MILLISECONDS);
            if (ttl == null || ttl <= 0) {
                return false;
            }

            stringRedisTemplate.opsForValue().set(
                    sessionKey, 
                    objectMapper.writeValueAsString(session), 
                    ttl, 
                    TimeUnit.MILLISECONDS
            );
            return true;
        } catch (Exception e) {
            log.error("Failed to validate and update session ID {}", jti, e);
            return false;
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
