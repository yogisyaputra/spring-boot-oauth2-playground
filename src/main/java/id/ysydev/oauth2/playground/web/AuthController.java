package id.ysydev.oauth2.playground.web;

import id.ysydev.oauth2.playground.security.CookieUtil;
import id.ysydev.oauth2.playground.security.JwtService;
import id.ysydev.oauth2.playground.security.RedisTokenStore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

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

    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest req, @RequestHeader(value = "Authorization", required = false) String authz) {
        String jwt = resolveToken(req, authz);
        if (!StringUtils.hasText(jwt)) return Map.of("status", "no-token");
        try {
            Claims c = jwtService.parse(jwt).getBody();
            String jti = c.getId();
            if (StringUtils.hasText(jti)) tokenStore.revoke(jti);
            return Map.of("status", "ok");
        } catch (Exception e) {
            return Map.of("status", "invalid-token");
        }
    }

    @PostMapping("/api/auth/logout")
    public Map<String, Object> logout(HttpServletRequest req, HttpServletResponse res,
                                      @Value("${app.jwt.cookie-name:ACCESS_TOKEN}") String cookieName,
                                      @Value("${app.cookie.secure:false}") boolean cookieSecure,
                                      @Value("${app.cookie.same-site:Lax}") String sameSite,
                                      @RequestHeader(value = "Authorization", required = false) String authz) {
        String jwt = extractFromCookieOrBearer(req, cookieName, authz);
        if (!StringUtils.hasText(jwt)) {
            // tetap hapus cookie kalau ada
            CookieUtil.deleteCookie(res, cookieName, "/", cookieSecure, sameSite);
            return Map.of("status", "no-token");
        }
        try {
            Claims claims = jwtService.parse(jwt).getBody();
            String jti = claims.getId();
            if (StringUtils.hasText(jti)) tokenStore.revoke(jti);
            CookieUtil.deleteCookie(res, cookieName, "/", cookieSecure, sameSite);
            return Map.of("status", "ok");
        } catch (Exception e) {
            CookieUtil.deleteCookie(res, cookieName, "/", cookieSecure, sameSite);
            return Map.of("status", "invalid-token");
        }
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
