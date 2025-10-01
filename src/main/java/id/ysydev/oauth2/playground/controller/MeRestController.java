package id.ysydev.oauth2.playground.controller;

import id.ysydev.oauth2.playground.user.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class MeRestController {
    private final UserService userService;
    public MeRestController(UserService userService) { this.userService = userService; }

    @GetMapping("/me")
    public Map<String, Object> me(Authentication auth) {
        if (auth == null) return Map.of("error", "unauthenticated");

        String uid = auth.getName(); // subject dari JWT (di-set oleh JwtAuthenticationFilter)
        try {
            return userService.findById(UUID.fromString(uid))
                    .<Map<String, Object>>map(u -> Map.of(
                            "id", u.getId(),
                            "email", u.getEmail(),
                            "role", u.getRole(),
                            "name", u.getName(),
                            "avatarUrl", u.getAvatarUrl()
                    ))
                    .orElse(Map.of("error", "user-not-found"));
        } catch (IllegalArgumentException e) {
            // kalau subject bukan UUID valid
            return Map.of("error", "invalid-user-id");
        }
    }


}
