package id.ysydev.oauth2.playground.security;

import jakarta.servlet.http.HttpServletResponse;

// security/CookieUtil.java
public final class CookieUtil {
    private CookieUtil(){}
    public static void addCookie(HttpServletResponse res, String name, String value,
                                 int maxAge, String path, boolean httpOnly, boolean secure,
                                 String sameSite, String domain) {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append("=").append(value != null ? value : "");
        if (domain != null && !domain.isEmpty()) sb.append("; Domain=").append(domain);
        if (path != null) sb.append("; Path=").append(path);
        if (maxAge >= 0) sb.append("; Max-Age=").append(maxAge);
        if (secure) sb.append("; Secure");
        if (httpOnly) sb.append("; HttpOnly");
        if (sameSite != null) sb.append("; SameSite=").append(sameSite);
        res.addHeader("Set-Cookie", sb.toString());
    }
}

