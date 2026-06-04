package org.teamzemo.scarletauth.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

@Component
public class CookieUtils {

    private static final String ACCESS_TOKEN_COOKIE = "access_token";
    private static final String REFRESH_TOKEN_COOKIE = "refresh_token";
    private static final int ACCESS_TOKEN_MAX_AGE = 900; // 15 min
    private static final int REFRESH_TOKEN_MAX_AGE = 604800; // 7 days

    public void setAccessTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = createSecureCookie(ACCESS_TOKEN_COOKIE, token, ACCESS_TOKEN_MAX_AGE);
        response.addCookie(cookie);
    }

    public void setRefreshTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = createSecureCookie(REFRESH_TOKEN_COOKIE, token, REFRESH_TOKEN_MAX_AGE);
        response.addCookie(cookie);
    }

    public void clearAuthCookies(HttpServletResponse response) {
        Cookie accessCookie = createSecureCookie(ACCESS_TOKEN_COOKIE, "", 0);
        Cookie refreshCookie = createSecureCookie(REFRESH_TOKEN_COOKIE, "", 0);
        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
    }

    private Cookie createSecureCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // Set to true in production (HTTPS)
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "Lax");
        return cookie;
    }
}
