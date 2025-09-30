package id.ysydev.oauth2.playground.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class RedisTokenStore {

    private final StringRedisTemplate redis;
    private final String keyPrefix = "auth:jwt:"; // namespace
    private final long ttlSeconds;

    public RedisTokenStore(StringRedisTemplate redis,
                           @Value("${app.jwt.expires-minutes:60}") long expiresMinutes) {
        this.redis = redis;
        this.ttlSeconds = expiresMinutes * 60;
    }

    public void put(String jti, String userId) {
        String key = keyPrefix + jti;
        redis.opsForValue().set(key, userId, Duration.ofSeconds(ttlSeconds));
    }

    public boolean exists(String jti) {
        Boolean has = redis.hasKey(keyPrefix + jti);
        return Boolean.TRUE.equals(has);
    }

    public void revoke(String jti) {
        redis.delete(keyPrefix + jti);
    }

    public void revokeAllForUser(String userId) {
        // optional: kalau mau revoke massal, perlu scan keys
        // Hati-hati: SCAN adalah O(n). Implement kalau memang dibutuhkan.
    }
}
