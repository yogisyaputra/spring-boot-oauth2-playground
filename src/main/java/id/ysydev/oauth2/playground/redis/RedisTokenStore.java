package id.ysydev.oauth2.playground.redis;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

// security/RedisTokenStore.java
@Component
public class RedisTokenStore {
    private final StringRedisTemplate redis;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private static final String ACCESS_PREFIX = "auth:jwt:";    // access prefix
    private static final String REFRESH_PREFIX = "auth:refresh:";  // refresh prefix

    public RedisTokenStore(StringRedisTemplate redis,
                           @Value("${app.jwt.access-expires-minutes:15}") long accessTtlSeconds,
                           @Value("${app.jwt.refresh-expires-days:14}") long refreshTtlSeconds) {
        this.redis = redis;
        this.accessTtlSeconds = accessTtlSeconds * 60;
        this.refreshTtlSeconds = refreshTtlSeconds * 24 * 60 * 60;
    }

    public void revokeAccess(String jti) {
        redis.delete(ACCESS_PREFIX + jti);
    }

    public void putRefresh(String jti, String uid) {
        redis.opsForValue().set(REFRESH_PREFIX + jti, uid, Duration.ofSeconds(refreshTtlSeconds));
    }

    public String getRefreshOwner(String jti) {
        return redis.opsForValue().get(REFRESH_PREFIX + jti);
    }

    public void revokeRefresh(String jti) {
        redis.delete(REFRESH_PREFIX + jti);
    }

    public void putAccessPair(String jti, String uid, String sid) {
        redis.opsForValue().set(ACCESS_PREFIX + jti, uid + "|" + sid, Duration.ofSeconds(accessTtlSeconds));
    }

    public boolean accessPairValid(String jti, String sid) {
        String val = redis.opsForValue().get(ACCESS_PREFIX + jti);
        if (val == null) return false;
        int p = val.indexOf('|');
        if (p < 0) return false;
        String savedSid = val.substring(p + 1);
        return savedSid.equals(sid);
    }
}
