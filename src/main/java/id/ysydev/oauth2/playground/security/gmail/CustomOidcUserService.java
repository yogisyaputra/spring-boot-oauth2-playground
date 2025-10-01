package id.ysydev.oauth2.playground.security.gmail;

import id.ysydev.oauth2.playground.user.*;
import id.ysydev.oauth2.playground.user_provider.UserProviderAccount;
import id.ysydev.oauth2.playground.user_provider.UserProviderAccountService;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
public class CustomOidcUserService extends OidcUserService {

    private final UserService userService;
    private final UserProviderAccountService accountService;

    public CustomOidcUserService(UserService userService, UserProviderAccountService accountService) {
        this.userService = userService;
        this.accountService = accountService;
    }

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) {
        // panggil OidcUserService default (ambil id token + userinfo)
        OidcUser oidcUser = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId(); // "google"
        // Atribut Google (OIDC): sub, email, name, picture, dll
        String providerUserId = oidcUser.getSubject();
        String email = oidcUser.getEmail();
        String name = oidcUser.getFullName();
        String avatarUrl = oidcUser.getPicture();

        if (email == null || email.isEmpty()) {
            throw new RuntimeException("Email not found from provider " + registrationId);
        }

        // upsert users
        User user = userService.findByEmail(email).orElseGet(() -> {
            User u = new User();
            u.setId(UUID.randomUUID());
            u.setEmail(email);
            u.setCreatedAt(OffsetDateTime.now());
            return u;
        });
        user.setName(name);
        user.setAvatarUrl(avatarUrl);
        user.setLastLoginAt(OffsetDateTime.now());
        user = userService.saveAndFlush(user);

        // upsert provider account
        User finalUser = user;
        UserProviderAccount acc = accountService
                .findByProviderAndProviderUserId(registrationId, providerUserId)
                .orElseGet(() -> {
                    UserProviderAccount a = new UserProviderAccount();
                    a.setId(UUID.randomUUID());
                    a.setProvider(registrationId);
                    a.setProviderUserId(providerUserId);
                    a.setUser(finalUser);
                    return a;
                });
        accountService.saveAndFlush(acc);

        // sisipkan app_user_id sebagai claim tambahan agar /api/me bisa baca
        OidcIdToken idToken = oidcUser.getIdToken();
        OidcUserInfo userInfo = oidcUser.getUserInfo();

        // Bungkus kembali sebagai DefaultOidcUser, tambahkan authority & claim ekstra via attributes
        Set<SimpleGrantedAuthority> authorities = Set.of(new SimpleGrantedAuthority("ROLE_USER"));
        HashMap<String,Object> mapped = new HashMap<>(oidcUser.getClaims());
        mapped.put("app_user_id", user.getId().toString());

        // kembalikan OIDC user dengan claims yang sudah diperkaya
        return new DefaultOidcUser(authorities, idToken, userInfo, "sub") {
            @Override
            public Map<String, Object> getAttributes() {
                return mapped;
            }
        };
    }
}
