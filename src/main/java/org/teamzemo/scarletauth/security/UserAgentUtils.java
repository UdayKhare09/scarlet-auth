package org.teamzemo.scarletauth.security;

public class UserAgentUtils {

    public static String parseBrowser(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) return "Unknown";
        String ua = userAgent.toLowerCase();
        if (ua.contains("scarletandroid")) return "App";
        if (ua.contains("edg/")) return "Edge";
        if (ua.contains("chrome/") || ua.contains("chromium/")) return "Chrome";
        if (ua.contains("firefox/")) return "Firefox";
        if (ua.contains("safari/") && !ua.contains("chrome/") && !ua.contains("chromium/")) return "Safari";
        return "Browser";
    }

    public static String parseOs(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) return "Unknown";
        String ua = userAgent.toLowerCase();
        if (ua.contains("scarletandroid")) return "Android";
        if (ua.contains("windows")) return "Windows";
        if (ua.contains("macintosh") || ua.contains("mac os x")) return "macOS";
        if (ua.contains("linux")) return "Linux";
        if (ua.contains("android")) return "Android";
        if (ua.contains("iphone") || ua.contains("ipad")) return "iOS";
        return "OS";
    }

    public static String parseDevice(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) return "Unknown";
        String ua = userAgent.toLowerCase();
        if (ua.contains("scarletandroid")) return "Mobile";
        if (ua.contains("mobile") || ua.contains("android") || ua.contains("iphone")) return "Mobile";
        if (ua.contains("ipad") || ua.contains("tablet")) return "Tablet";
        return "Desktop";
    }
}
