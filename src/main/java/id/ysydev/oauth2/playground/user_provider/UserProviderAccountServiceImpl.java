package id.ysydev.oauth2.playground.user_provider;

import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Service
public class UserProviderAccountServiceImpl implements UserProviderAccountService{

    @Resource
    private UserProviderAccountRepository userProviderAccountRepository;

    @Override
    public Optional<UserProviderAccount> findByProviderAndProviderUserId(String registrationId, String providerUserId) {
        return userProviderAccountRepository.findByProviderAndProviderUserId(registrationId, providerUserId);
    }

    @Override
    public void saveAndFlush(UserProviderAccount account) {
        userProviderAccountRepository.saveAndFlush(account);
    }
}
