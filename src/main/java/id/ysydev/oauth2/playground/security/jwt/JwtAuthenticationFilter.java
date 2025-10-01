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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

// security/JwtAuthenticationFilter.java
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwt; private final RedisTokenStore store; private final String accessCookieName;
    public JwtAuthenticationFilter(JwtService jwt, RedisTokenStore store, String accessCookieName) {
        this.jwt = jwt; this.store = store; this.accessCookieName = accessCookieName;
    }
    @Override protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String token = readCookie(req, accessCookieName);
        if (token != null) {
            try {
                Claims c = jwt.parse(token).getBody();
                if ("access".equals(c.get("typ")) && store.accessExists(c.getId())) {
                    String uid = c.getSubject();
                    String roles = (String) c.get("roles"); // bisa null untuk token lama
                    List<GrantedAuthority> auths = new ArrayList<>();
                    if (roles == null || roles.isEmpty()) {
                        auths.add(new SimpleGrantedAuthority("ROLE_USER")); // backward compat
                    } else {
                        for (String r : roles.split(",")) {
                            auths.add(new SimpleGrantedAuthority("ROLE_" + r.trim()));
                        }
                    }
                    var auth = new UsernamePasswordAuthenticationToken(uid, null, auths);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (Exception ignored) {}
        }
        chain.doFilter(req, res);
    }
    private String readCookie(HttpServletRequest req, String name) {
        if (req.getCookies()==null) return null;
        for (Cookie c : req.getCookies()) if (name.equals(c.getName())) return c.getValue();
        return null;
    }
}
