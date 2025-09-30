package id.ysydev.oauth2.playground.security;

import jakarta.servlet.http.HttpServletResponse;

public final class CookieUtil {
    private CookieUtil() {}

    public static void addCookie(HttpServletResponse res, String name, String value,
                                 int maxAgeSeconds, String path,
                                 boolean httpOnly, boolean secure,
                                 String sameSite /* Lax | Strict | None | null */) {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append("=").append(value != null ? value : "");
        if (path != null) sb.append("; Path=").append(path);
        if (maxAgeSeconds >= 0) sb.append("; Max-Age=").append(maxAgeSeconds);
        if (secure) sb.append("; Secure");
        if (httpOnly) sb.append("; HttpOnly");
        if (sameSite != null) sb.append("; SameSite=").append(sameSite);
        res.addHeader("Set-Cookie", sb.toString());
    }

    public static void deleteCookie(HttpServletResponse res, String name, String path,
                                    boolean secure, String sameSite) {
        addCookie(res, name, "", 0, path, true, secure, sameSite);
    }
}
