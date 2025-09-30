package id.ysydev.oauth2.playground.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

// security/JwtService.java
@Service
public class JwtService {
    private final Key key;
    private final String issuer;
    private final long accessMinutes;
    private final long refreshDays;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.access-expires-minutes:15}") long accessMinutes,
                      @Value("${app.jwt.refresh-expires-days:14}") long refreshDays,
                      @Value("${app.jwt.issuer:oauth-demo}") String issuer) {
        if (secret == null || secret.length() < 32) throw new IllegalArgumentException("secret too short");
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessMinutes = accessMinutes;
        this.refreshDays = refreshDays;
        this.issuer = issuer;
    }

    public String newJti() { return UUID.randomUUID().toString(); }

    public String createAccess(String uid, String jti, Map<String,Object> claims) {
        return create(uid, jti, claims, accessMinutes * 60, "access");
    }
    public String createRefresh(String uid, String jti) {
        return create(uid, jti, Map.of(), refreshDays * 24 * 60 * 60, "refresh");
    }

    private String create(String uid, String jti, Map<String,Object> claims, long ttlSeconds, String typ) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setIssuer(issuer)
                .setId(jti).setSubject(uid)
                .addClaims(claims).claim("typ", typ)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(ttlSeconds)))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Jws<Claims> parse(String jwt) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt);
    }
}
