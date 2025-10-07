package id.ysydev.oauth2.playground.security.jwt;

import id.ysydev.oauth2.playground.redis.RedisTokenStore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final RedisTokenStore tokenStore;
    private final String accessCookieName;
    private final String sessionCookieName;

    public JwtAuthenticationFilter(JwtService jwt, RedisTokenStore store, String accessCookieName, String sessionCookieName) {
        this.jwtService = jwt;
        this.tokenStore = store;
        this.accessCookieName = accessCookieName;
        this.sessionCookieName = sessionCookieName;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String accessJwt = readCookie(request, accessCookieName);
        String sid = readCookie(request, sessionCookieName); // wajib ada

        if (StringUtils.hasText(accessJwt) && StringUtils.hasText(sid)) {
            try {
                Jws<Claims> parsed = jwtService.parse(accessJwt);
                Claims c = parsed.getBody();
                if (!"access".equals(c.get("typ"))) throw new RuntimeException("not access token");
                String jti = c.getId();
                if (StringUtils.hasText(jti) && tokenStore.accessPairValid(jti, sid)) {
                    String uid = c.getSubject();

                    List<SimpleGrantedAuthority> auths = new ArrayList<>();
                    String roles = (String) c.get("roles");
                    if (!StringUtils.hasText(roles)) auths.add(new SimpleGrantedAuthority("ROLE_USER"));
                    else for (String r : roles.split(",")) auths.add(new SimpleGrantedAuthority("ROLE_" + r.trim()));

                    var auth = new UsernamePasswordAuthenticationToken(uid, null, auths);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (Exception ignored) {
            }
        }
        chain.doFilter(request, res);
    }

    private String readCookie(HttpServletRequest req, String name) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) if (name.equals(c.getName())) return c.getValue();
        return null;
    }
}
