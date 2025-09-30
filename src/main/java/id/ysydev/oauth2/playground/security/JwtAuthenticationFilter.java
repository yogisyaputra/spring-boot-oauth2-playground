package id.ysydev.oauth2.playground.security;

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
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final RedisTokenStore tokenStore;
    private final String cookieName;

    public JwtAuthenticationFilter(JwtService jwtService, RedisTokenStore tokenStore, String cookieName) {
        this.jwtService = jwtService;
        this.tokenStore = tokenStore;
        this.cookieName = cookieName;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String jwt = resolveTokenFromCookie(request);
        if (jwt != null) {
            try {
                Jws<Claims> parsed = jwtService.parse(jwt);
                Claims c = parsed.getBody();
                String jti = c.getId();
                if (StringUtils.hasText(jti) && tokenStore.exists(jti)) {
                    String uid = c.getSubject();
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(uid, null,
                            List.of(new SimpleGrantedAuthority("ROLE_USER")));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (Exception ignored) {
                // Biarkan unauthenticated => 401 di entry point bila endpoint butuh auth
            }
        }
        chain.doFilter(request, response);
    }

    private String resolveTokenFromCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (cookieName.equals(c.getName()) && StringUtils.hasText(c.getValue())) return c.getValue();
        }
        return null;
    }
}
