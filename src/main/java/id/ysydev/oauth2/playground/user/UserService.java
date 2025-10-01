package id.ysydev.oauth2.playground.user;

import java.util.Optional;
import java.util.UUID;

public interface UserService {
    Optional<User> findById(UUID uuid);

    void save(User u);

    Optional<User> findByEmail(String email);

    User saveAndFlush(User user);
}
