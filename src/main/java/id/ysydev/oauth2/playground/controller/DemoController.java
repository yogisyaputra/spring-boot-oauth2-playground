package id.ysydev.oauth2.playground.controller;

import id.ysydev.oauth2.playground.user.UserProfileService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class DemoController {

    private final UserProfileService userProfileService;

    public DemoController(UserProfileService userProfileService) {
        this.userProfileService = userProfileService;
    }

    // === ADMIN ONLY via @PreAuthorize ===
    @GetMapping("/admin/stats")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> adminStats() {
        return Map.of(
                "users", 123,
                "activeTokens", 45,
                "version", "1.0.0"
        );
    }

    // === USER: hanya boleh akses profil miliknya sendiri ===
    // Rule: path variable {id} harus sama dengan subject JWT (Authentication.name)
    @GetMapping("/users/{id}")
    @PreAuthorize("#id == authentication.name or hasRole('ADMIN')")
    public Map<String, Object> getUser(@PathVariable("id") String id) {
        return userProfileService.getUserProfile(id);
    }

    // === USER: update miliknya sendiri (atau ADMIN) ===
    @PutMapping("/users/{id}")
    @PreAuthorize("#id == authentication.name or hasRole('ADMIN')")
    public Map<String, Object> updateUser(@PathVariable String id, @RequestBody Map<String, Object> body) {
        String name = (String) body.getOrDefault("name", "");
        return userProfileService.updateUser(UUID.fromString(id), name);
    }
}
