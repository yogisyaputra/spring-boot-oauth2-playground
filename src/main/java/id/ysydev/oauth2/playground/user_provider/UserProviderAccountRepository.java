package id.ysydev.oauth2.playground.user_provider;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface UserProviderAccountRepository extends JpaRepository<UserProviderAccount, UUID> {
    Optional<UserProviderAccount> findByProviderAndProviderUserId(String provider, String providerUserId);
}
