package id.ysydev.oauth2.playground.redis;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

// security/RedisTokenStore.java
@Component
public class RedisTokenStore {
    private final StringRedisTemplate redis;
    private final long accessTtl;
    private final long refreshTtl;
    private static final String A = "auth:jwt:";      // access prefix
    private static final String R = "auth:refresh:";  // refresh prefix

    public RedisTokenStore(StringRedisTemplate redis,
                           @Value("${app.jwt.access-expires-minutes:15}") long accessMin,
                           @Value("${app.jwt.refresh-expires-days:14}") long refreshDays) {
        this.redis = redis;
        this.accessTtl = accessMin * 60;
        this.refreshTtl = refreshDays * 24 * 60 * 60;
    }
    // ACCESS
    public void putAccess(String jti, String uid) { redis.opsForValue().set(A+jti, uid, Duration.ofSeconds(accessTtl)); }
    public boolean accessExists(String jti) { return Boolean.TRUE.equals(redis.hasKey(A+jti)); }
    public void revokeAccess(String jti) { redis.delete(A+jti); }
    // REFRESH
    public void putRefresh(String jti, String uid) { redis.opsForValue().set(R+jti, uid, Duration.ofSeconds(refreshTtl)); }
    public String ownerOfRefresh(String jti) { return redis.opsForValue().get(R+jti); }
    public void revokeRefresh(String jti) { redis.delete(R+jti); }
}
