package id.ysydev.oauth2.playground.security;

import id.ysydev.oauth2.playground.user.User;
import id.ysydev.oauth2.playground.user.UserProviderAccount;
import id.ysydev.oauth2.playground.user.UserProviderAccountRepository;
import id.ysydev.oauth2.playground.user.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;

import java.time.OffsetDateTime;
import java.util.*;

@Slf4j
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final UserProviderAccountRepository accountRepository;

    public CustomOAuth2UserService(UserRepository userRepository, UserProviderAccountRepository accountRepository) {
        this.userRepository = userRepository;
        this.accountRepository = accountRepository;
    }

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // delegate ke default loader dulu
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oauth2User = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId(); // google | github
        Map<String, Object> attributes = new HashMap<>(oauth2User.getAttributes());

        String providerUserId;
        String email ;
        String name;
        String avatarUrl = null;
        String username = null;
        String profileUrl = null;

        if ("google".equals(registrationId)) {
            providerUserId = (String) attributes.get("sub");
            email = (String) attributes.get("email");
            name = (String) attributes.get("name");
            avatarUrl = (String) attributes.get("picture");
        } else if ("github".equals(registrationId)) {
            providerUserId = String.valueOf(attributes.get("id"));
            email = (String) attributes.get("email"); // bisa null
            name = (String) attributes.getOrDefault("name", attributes.get("login"));
            avatarUrl = (String) attributes.get("avatar_url");
            username = (String) attributes.get("login");
            profileUrl = (String) attributes.get("html_url");

            // === Tambahan: fetch email jika null ===
            if (email == null || email.isEmpty()) {
                String accessToken = userRequest.getAccessToken().getTokenValue();
                email = fetchGithubEmail(accessToken);
                if (email != null) {
                    attributes.put("email", email); // supaya success handler dapat email juga
                }
            }
        } else {
            throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
        }

        if (email == null || email.isEmpty()) {
            throw new OAuth2AuthenticationException("Email not found from provider " + registrationId);
        }

        // Upsert user
        String finalEmail = email;
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User u = new User();
            u.setId(UUID.randomUUID());
            u.setEmail(finalEmail);
            u.setCreatedAt(OffsetDateTime.now());
            return u;
        });
        user.setName(name);
        user.setAvatarUrl(avatarUrl);
        user.setLastLoginAt(OffsetDateTime.now());
        user = userRepository.saveAndFlush(user);
        log.info("Upsert user: id={} email={}", user.getId(), user.getEmail());


        // Upsert provider account
        User finalUser = user;
        UserProviderAccount account = accountRepository
                .findByProviderAndProviderUserId(registrationId, providerUserId)
                .orElseGet(() -> {
                    UserProviderAccount acc = new UserProviderAccount();
                    acc.setId(UUID.randomUUID());
                    acc.setProvider(registrationId);
                    acc.setProviderUserId(providerUserId);
                    acc.setUser(finalUser);
                    return acc;
                });
        account.setUsername(username);
        account.setProfileUrl(profileUrl);
        accountRepository.saveAndFlush(account);
        log.info("Upsert account: provider={} providerUserId={} userId={}",
                registrationId, providerUserId, user.getId());

        // Tambahkan app_user_id ke atribut supaya bisa dipakai di /api/me
        attributes.put("app_user_id", user.getId().toString());
        String nameAttr =
                userRequest.getClientRegistration()
                        .getProviderDetails()
                        .getUserInfoEndpoint()
                        .getUserNameAttributeName(); // google: sub, github: id
        return new DefaultOAuth2User(
                Set.of(new SimpleGrantedAuthority("ROLE_USER")),
                attributes,
                nameAttr
        );
    }


    /** Panggil GitHub API: GET https://api.github.com/user/emails
     *  Header:
     *    Authorization: token <accessToken>
     *    Accept: application/vnd.github+json
     */
    private String fetchGithubEmail(String accessToken) {
        RestClient client = RestClient.create(); // Spring 6+ (jika tidak ada: pakai RestTemplate)
        try {
            GithubEmail[] emails = client.get()
                    .uri("https://api.github.com/user/emails")
                    .header("Authorization", "token " + accessToken)
                    .header("Accept", "application/vnd.github+json")
                    .retrieve()
                    .body(GithubEmail[].class);

            if (emails == null || emails.length == 0) return null;

            // 1) primary && verified
            for (GithubEmail e : emails)
                if (e.getPrimary() && e.getVerified()) return e.getEmail();

            // 2) verified pertama
            for (GithubEmail e : emails)
                if (e.getVerified()) return e.getEmail();

            // 3) fallback ke item pertama
            return emails[0].getEmail();
        } catch (Exception ex) {
            // bisa log warn di sini, tapi jangan fail keras
            return null;
        }
    }
}
