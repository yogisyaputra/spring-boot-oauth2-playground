package id.ysydev.oauth2.playground.security;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component("_deviceSec")
public class DeviceSecurity {
    private final StringRedisTemplate redis;
    public DeviceSecurity(StringRedisTemplate redis) { this.redis = redis; }

    public boolean canManageDevice(String sid, org.springframework.security.core.Authentication auth) {
        if (auth == null || sid == null) return false;
        String uid = auth.getName();
        // cek membership user->sid
        return Boolean.TRUE.equals(
                redis.opsForSet().isMember("auth:user:%s:sessions".formatted(uid), sid)
        );
    }
}
