package id.ysydev.oauth2.playground.user;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Service
public class UserProfileService {

    private final UserService userService;

    public UserProfileService(UserService userService) {
        this.userService = userService;
    }

    // Hanya pemilik UID atau ADMIN yang boleh ambil detail sensitif
    @PreAuthorize("#userId == authentication.name or hasRole('ADMIN')")
    public Map<String, Object> getUserProfile(String userId) {
        User u = userService.findById(UUID.fromString(userId)).orElseThrow();
        return Map.of(
                "id", u.getId(),
                "email", u.getEmail(),
                "name", u.getName(),
                "avatarUrl", u.getAvatarUrl(),
                "role", u.getRole()
        );
    }

    // Contoh update
    @PreAuthorize("#userId.toString() == authentication.name or hasRole('ADMIN')")
    public Map<String, Object> updateUser(UUID userId, String newName) {
        User u = userService.findById(userId).orElseThrow();
        u.setName(newName);
        userService.save(u);
        return Map.of("status", "ok", "id", u.getId(), "name", u.getName());
    }

    // (cek hasil setelah method jalan):
    @PostAuthorize("returnObject['id'].toString() == authentication.name or hasRole('ADMIN')")
    public Map<String, Object> getSensitive(UUID id) {
        var u = userService.findById(id).orElseThrow();
        return Map.of("id", u.getId(), "secret", "top-secret");
    }
}
