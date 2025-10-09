package id.ysydev.oauth2.playground.redis;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

// security/RedisTokenStore.java
@Component
public class RedisTokenStore {
    private final StringRedisTemplate redis;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;

    private static final String ACCESS_PREFIX = "auth:jwt:";           // jti -> uid|sid
    private static final String REFRESH_PREFIX = "auth:refresh:";       // jti -> uid|sid
    private static final String SESSION_HASH = "auth:session:";       // sid -> hash (uid, ua, ip, createdAt, lastSeen)
    private static final String SESSION_A_SET = "auth:session:%s:access";  // -> set of access jti
    private static final String SESSION_R_SET = "auth:session:%s:refresh"; // -> set of refresh jti
    private static final String USER_SESSIONS = "auth:user:%s:sessions";   // uid -> set of sid


    public RedisTokenStore(StringRedisTemplate redis,
                           @Value("${app.jwt.access-expires-minutes:15}") long accessTtlSeconds,
                           @Value("${app.jwt.refresh-expires-days:14}") long refreshTtlSeconds) {
        this.redis = redis;
        this.accessTtlSeconds = accessTtlSeconds * 60;
        this.refreshTtlSeconds = refreshTtlSeconds * 24 * 60 * 60;
    }

    // === Session metadata ===
    public void createSession(String sid, String uid, String ua, String ip) {
        var key = SESSION_HASH + sid;
        var map = new java.util.HashMap<String, String>();
        map.put("uid", uid);
        map.put("ua", ua == null ? "" : ua);
        map.put("ip", ip == null ? "" : ip);
        map.put("createdAt", java.time.Instant.now().toString());
        map.put("lastSeen", java.time.Instant.now().toString());
        redis.opsForHash().putAll(key, map);
        redis.opsForSet().add(USER_SESSIONS.formatted(uid), sid);
    }

    public void touchSession(String sid) {
        redis.opsForHash().put(SESSION_HASH + sid, "lastSeen", java.time.Instant.now().toString());
    }

    public java.util.List<java.util.Map<String, String>> listSessions(String uid) {
        var sids = redis.opsForSet().members(USER_SESSIONS.formatted(uid));
        if (sids == null) return java.util.List.of();
        var out = new java.util.ArrayList<java.util.Map<String, String>>();
        for (String sid : sids) {
            var entries = redis.<Object, Object>opsForHash().entries(SESSION_HASH + sid);
            if (entries != null && !entries.isEmpty()) {
                var m = new java.util.HashMap<String, String>();
                entries.forEach((k, v) -> m.put(String.valueOf(k), String.valueOf(v)));
                m.put("sid", sid);
                out.add(m);
            }
        }
        // optional: sort by lastSeen desc
        out.sort((a, b) -> b.getOrDefault("lastSeen", "").compareTo(a.getOrDefault("lastSeen", "")));
        return out;
    }

    public void deleteSessionCompletely(String uid, String sid) {
        // revoke all access tokens for this sid
        var accessSetKey = SESSION_A_SET.formatted(sid);
        var refreshSetKey = SESSION_R_SET.formatted(sid);

        var accessJtis = redis.opsForSet().members(accessSetKey);
        if (accessJtis != null) for (String jti : accessJtis) redis.delete(ACCESS_PREFIX + jti);
        var refreshJtis = redis.opsForSet().members(refreshSetKey);
        if (refreshJtis != null) for (String jti : refreshJtis) redis.delete(REFRESH_PREFIX + jti);

        redis.delete(accessSetKey);
        redis.delete(refreshSetKey);
        redis.delete(SESSION_HASH + sid);
        redis.opsForSet().remove(USER_SESSIONS.formatted(uid), sid);
    }

    // === ACCESS pair (jti ↔ uid|sid) + indeks sesi ===
    public void putAccessPair(String jti, String uid, String sid) {
        redis.opsForValue().set(ACCESS_PREFIX + jti, uid + "|" + sid, java.time.Duration.ofSeconds(accessTtlSeconds));
        redis.opsForSet().add(SESSION_A_SET.formatted(sid), jti);
    }

    public boolean accessPairValid(String jti, String sid) {
        String val = redis.opsForValue().get(ACCESS_PREFIX + jti);
        if (val == null) return false;
        int p = val.indexOf('|');
        if (p < 0) return false;
        String savedSid = val.substring(p + 1);
        return savedSid.equals(sid);
    }

    public void revokeAccess(String jti) {
        // best-effort: remove from session set jika tahu sid (opsional; tetap dihapus key utamanya)
        String val = redis.opsForValue().get(ACCESS_PREFIX + jti);
        if (val != null) {
            int p = val.indexOf('|');
            if (p > 0) {
                String sid = val.substring(p + 1);
                redis.opsForSet().remove(SESSION_A_SET.formatted(sid), jti);
            }
        }
        redis.delete(ACCESS_PREFIX + jti);
    }

    // === REFRESH pair (jti ↔ uid|sid) + indeks sesi ===
    public void putRefreshPair(String jti, String uid, String sid) {
        redis.opsForValue().set(REFRESH_PREFIX + jti, uid + "|" + sid, java.time.Duration.ofSeconds(refreshTtlSeconds));
        redis.opsForSet().add(SESSION_R_SET.formatted(sid), jti);
    }

    /**
     * Back-compat: kembalikan hanya UID meski value uid|sid
     */
    public String getRefreshOwner(String jti) {
        String val = redis.opsForValue().get(REFRESH_PREFIX + jti);
        if (val == null) return null;
        int p = val.indexOf('|');
        return p < 0 ? val : val.substring(0, p);
    }

    public String getRefreshSid(String jti) {
        String val = redis.opsForValue().get(REFRESH_PREFIX + jti);
        if (val == null) return null;
        int p = val.indexOf('|');
        return p < 0 ? null : val.substring(p + 1);
    }

    public void revokeRefresh(String jti) {
        String val = redis.opsForValue().get(REFRESH_PREFIX + jti);
        if (val != null) {
            int p = val.indexOf('|');
            if (p > 0) {
                String sid = val.substring(p + 1);
                redis.opsForSet().remove(SESSION_R_SET.formatted(sid), jti);
            }
        }
        redis.delete(REFRESH_PREFIX + jti);
    }
}
