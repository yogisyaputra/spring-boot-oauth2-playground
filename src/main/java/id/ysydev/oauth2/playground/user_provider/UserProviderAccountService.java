package id.ysydev.oauth2.playground.user_provider;

import java.util.Optional;

public interface UserProviderAccountService {
    Optional<UserProviderAccount> findByProviderAndProviderUserId(String registrationId, String providerUserId);

    void saveAndFlush(UserProviderAccount account);
}
