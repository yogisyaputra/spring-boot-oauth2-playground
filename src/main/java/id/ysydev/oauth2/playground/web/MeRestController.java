package id.ysydev.oauth2.playground.web;

import id.ysydev.oauth2.playground.user.User;
import id.ysydev.oauth2.playground.user.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class MeRestController {
    private final UserRepository userRepository;
    public MeRestController(UserRepository userRepository) { this.userRepository = userRepository; }

    @GetMapping("/me")
    public Map<String, Object> me(Authentication auth) {
        if (auth == null) return Map.of("error", "unauthenticated");

        String uid = auth.getName(); // subject dari JWT (di-set oleh JwtAuthenticationFilter)
        try {
            return userRepository.findById(UUID.fromString(uid))
                    .<Map<String, Object>>map(u -> Map.of(
                            "id", u.getId(),
                            "email", u.getEmail(),
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
