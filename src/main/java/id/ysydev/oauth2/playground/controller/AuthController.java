package id.ysydev.oauth2.playground.controller;

import id.ysydev.oauth2.playground.redis.RedisTokenStore;
import id.ysydev.oauth2.playground.security.CookieUtil;
import id.ysydev.oauth2.playground.security.jwt.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtService jwtService;
    private final RedisTokenStore tokenStore;

    public AuthController(JwtService jwtService, RedisTokenStore tokenStore) {
        this.jwtService = jwtService;
        this.tokenStore = tokenStore;
    }

    // web/AuthController.java
    @PostMapping("/refresh")
    public Map<String, Object> refresh(HttpServletRequest req, HttpServletResponse res,
                                       @Value("${app.jwt.refresh-cookie-name:REFRESH_TOKEN}") String refreshCookieName,
                                       @Value("${app.jwt.access-cookie-name:ACCESS_TOKEN}") String accessCookieName,
                                       @Value("${app.jwt.access-expires-minutes:15}") long accessMin,
                                       @Value("${app.jwt.refresh-expires-days:14}") long refreshDays,
                                       @Value("${app.cookie.secure:false}") boolean cookieSecure,
                                       @Value("${app.cookie.same-site:Lax}") String sameSite,
                                       @Value("${app.cookie.domain:}") String cookieDomain) {

        String refresh = null;
        if (req.getCookies() != null)
            for (Cookie c : req.getCookies()) if (refreshCookieName.equals(c.getName())) refresh = c.getValue();
        if (refresh == null || refresh.isEmpty()) return Map.of("error", "no-refresh");

        try {
            Claims claims = jwtService.parse(refresh).getBody();
            if (!"refresh".equals(claims.get("typ"))) return Map.of("error", "not-refresh");
            String oldJti = claims.getId();
            String uid = claims.getSubject();
            String owner = tokenStore.ownerOfRefresh(oldJti);
            if (owner == null || !owner.equals(uid)) return Map.of("error", "refresh-revoked");

            // ROTATE
            tokenStore.revokeRefresh(oldJti);
            String newRefreshJti = jwtService.newJti();
            String newRefresh = jwtService.createRefresh(uid, newRefreshJti);
            tokenStore.putRefresh(newRefreshJti, uid);

            String newAccessJti = jwtService.newJti();
            String newAccess = jwtService.createAccess(uid, newAccessJti, Map.of());
            tokenStore.putAccess(newAccessJti, uid);

            int accessMaxAge = (int) (accessMin * 60);
            int refreshMaxAge = (int) (refreshDays * 24 * 60 * 60);
            String domain = (cookieDomain != null && !cookieDomain.isEmpty()) ? cookieDomain : null;

            CookieUtil.addCookie(res, accessCookieName, newAccess, accessMaxAge, "/", true, cookieSecure, sameSite, domain);
            CookieUtil.addCookie(res, refreshCookieName, newRefresh, refreshMaxAge, "/", true, cookieSecure, sameSite, domain);

            return Map.of("status", "ok");
        } catch (Exception e) {
            return Map.of("error", "invalid-refresh");
        }
    }


    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest req, HttpServletResponse res,
                                      @Value("${app.jwt.access-cookie-name:ACCESS_TOKEN}") String accessCookieName,
                                      @Value("${app.jwt.refresh-cookie-name:REFRESH_TOKEN}") String refreshCookieName,
                                      @Value("${app.cookie.secure:false}") boolean cookieSecure,
                                      @Value("${app.cookie.same-site:Lax}") String sameSite,
                                      @Value("${app.cookie.domain:}") String cookieDomain) {
        String access = null, refresh = null;
        if (req.getCookies() != null) for (Cookie c : req.getCookies()) {
            if (accessCookieName.equals(c.getName())) access = c.getValue();
            if (refreshCookieName.equals(c.getName())) refresh = c.getValue();
        }
        try {
            if (access != null) {
                Claims c = jwtService.parse(access).getBody();
                if ("access".equals(c.get("typ"))) tokenStore.revokeAccess(c.getId());
            }
        } catch (Exception ignored) {
        }
        try {
            if (refresh != null) {
                Claims c = jwtService.parse(refresh).getBody();
                if ("refresh".equals(c.get("typ"))) tokenStore.revokeRefresh(c.getId());
            }
        } catch (Exception ignored) {
        }
        String domain = (cookieDomain != null && !cookieDomain.isEmpty()) ? cookieDomain : null;
        CookieUtil.addCookie(res, accessCookieName, "", 0, "/", true, cookieSecure, sameSite, domain);
        CookieUtil.addCookie(res, refreshCookieName, "", 0, "/", true, cookieSecure, sameSite, domain);
        return Map.of("status", "ok");
    }

    private String extractFromCookieOrBearer(HttpServletRequest req, String cookieName, String authz) {
        if (StringUtils.hasText(authz) && authz.startsWith("Bearer ")) return authz.substring(7);
        if (req.getCookies() != null) {
            for (Cookie c : req.getCookies()) if (cookieName.equals(c.getName())) return c.getValue();
        }
        return null;
    }


    private String resolveToken(HttpServletRequest req, String authz) {
        if (StringUtils.hasText(authz) && authz.startsWith("Bearer ")) {
            return authz.substring(7);
        }
        if (req.getCookies() != null) {
            for (Cookie c : req.getCookies()) {
                if ("ACCESS_TOKEN".equals(c.getName()) && StringUtils.hasText(c.getValue())) {
                    return c.getValue();
                }
            }
        }
        return null;
    }
}
