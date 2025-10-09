package id.ysydev.oauth2.playground.controller;

import id.ysydev.oauth2.playground.redis.RedisTokenStore;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private final RedisTokenStore tokenStore;

    public DeviceController(RedisTokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    // List semua sesi (perangkat) milik user saat ini
    @GetMapping
    public List<Map<String, String>> listDevices(org.springframework.security.core.Authentication auth) {
        String uid = auth.getName(); // subject = userId
        return tokenStore.listSessions(uid);
    }

    // Logout satu perangkat (by sid)
    @DeleteMapping("/{sid}")
    @PreAuthorize("@_deviceSec.canManageDevice(#sid, authentication)")
    public Map<String, Object> logoutDevice(@PathVariable("sid") String sid,
                                            org.springframework.security.core.Authentication auth) {
        String uid = auth.getName();
        tokenStore.deleteSessionCompletely(uid, sid);
        return Map.of("status", "ok");
    }
}
