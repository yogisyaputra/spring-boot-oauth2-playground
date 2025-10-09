package id.ysydev.oauth2.playground.controller;

import id.ysydev.oauth2.playground.redis.RedisTokenStore;
import id.ysydev.oauth2.playground.security.CookieUtil;
import id.ysydev.oauth2.playground.security.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
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

    @PostMapping("/refresh")
    public Map<String, Object> refresh(HttpServletRequest req, HttpServletResponse res,
                                       @Value("${app.jwt.refresh-cookie-name:REFRESH_TOKEN}") String refreshCookieName,
                                       @Value("${app.jwt.access-cookie-name:ACCESS_TOKEN}") String accessCookieName,
                                       @Value("${app.session.cookie-name:SESSION_KEY}") String sessionCookieName,
                                       @Value("${app.jwt.access-expires-minutes:15}") long accessMin,
                                       @Value("${app.jwt.refresh-expires-days:14}") long refreshDays,
                                       @Value("${app.cookie.secure:false}") boolean cookieSecure,
                                       @Value("${app.cookie.same-site:Lax}") String sameSite,
                                       @Value("${app.cookie.domain:}") String cookieDomain) {

        String refreshJwt = readCookie(req, refreshCookieName);
        String sid = readCookie(req, sessionCookieName);
        if (refreshJwt == null || sid == null) return Map.of("error", "no-refresh-or-session");

        try {
            var claims = jwtService.parse(refreshJwt).getBody();
            if (!"refresh".equals(claims.get("typ"))) return Map.of("error", "not-refresh");

            String oldJti = claims.getId();
            String uid = claims.getSubject();
            String owner = tokenStore.getRefreshOwner(oldJti);
            if (owner == null || !owner.equals(uid)) return Map.of("error", "refresh-revoked");

            // ROTASI refresh
            tokenStore.revokeRefresh(oldJti);
            String newRefreshJti = jwtService.newJti();
            String newRefresh    = jwtService.createRefresh(uid, newRefreshJti);
            tokenStore.putRefreshPair(newRefreshJti, uid, sid);   // <— pakai pair dgn sid

            // ACCESS baru — pair dengan SID yang sama
            String newAccessJti = jwtService.newJti();
            String newAccess    = jwtService.createAccess(uid, newAccessJti, Map.of());
            tokenStore.putAccessPair(newAccessJti, uid, sid);

            int accessMaxAge = (int) (accessMin * 60);
            int refreshMaxAge = (int) (refreshDays * 24 * 60 * 60);
            String domain = (cookieDomain != null && !cookieDomain.isEmpty()) ? cookieDomain : null;

            CookieUtil.addCookie(res, accessCookieName, newAccess, accessMaxAge, "/", true, cookieSecure, sameSite, domain);
            CookieUtil.addCookie(res, refreshCookieName, newRefresh, refreshMaxAge, "/", true, cookieSecure, sameSite, domain);
            // Optional: refresh Max-Age SESSION_KEY biar seumur access
            CookieUtil.addCookie(res, sessionCookieName, sid, accessMaxAge, "/", true, cookieSecure, sameSite, domain);

            return Map.of("status", "ok");
        } catch (Exception e) {
            return Map.of("error", "invalid-refresh");
        }
    }

    private String readCookie(HttpServletRequest req, String name) {
        if (req.getCookies() == null) return null;
        for (var c : req.getCookies()) if (name.equals(c.getName())) return c.getValue();
        return null;
    }


    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest req, HttpServletResponse res,
                                      @Value("${app.jwt.access-cookie-name:ACCESS_TOKEN}") String accessCookieName,
                                      @Value("${app.jwt.refresh-cookie-name:REFRESH_TOKEN}") String refreshCookieName,
                                      @Value("${app.session.cookie-name:SESSION_KEY}") String sessionCookieName,
                                      @Value("${app.cookie.secure:false}") boolean cookieSecure,
                                      @Value("${app.cookie.same-site:Lax}") String sameSite,
                                      @Value("${app.cookie.domain:}") String cookieDomain) {
        String accessJwt = readCookie(req, accessCookieName);
        String refreshJwt = readCookie(req, refreshCookieName);

        try {
            if (accessJwt != null) {
                var c = jwtService.parse(accessJwt).getBody();
                if ("access".equals(c.get("typ"))) tokenStore.revokeAccess(c.getId());
            }
        } catch (Exception ignore) {
        }
        try {
            if (refreshJwt != null) {
                var c = jwtService.parse(refreshJwt).getBody();
                if ("refresh".equals(c.get("typ"))) tokenStore.revokeRefresh(c.getId());
            }
        } catch (Exception ignore) {
        }

        String domain = (cookieDomain != null && !cookieDomain.isEmpty()) ? cookieDomain : null;
        CookieUtil.addCookie(res, accessCookieName, "", 0, "/", true, cookieSecure, sameSite, domain);
        CookieUtil.addCookie(res, refreshCookieName, "", 0, "/", true, cookieSecure, sameSite, domain);
        CookieUtil.addCookie(res, sessionCookieName, "", 0, "/", true, cookieSecure, sameSite, domain);

        return Map.of("status", "ok");
    }
}
