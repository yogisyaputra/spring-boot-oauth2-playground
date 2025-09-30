package id.ysydev.oauth2.playground.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Map;

@Component
public class OAuth2AuthenticationSuccessHandler implements org.springframework.security.web.authentication.AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final RedisTokenStore tokenStore;
    private final HttpCookieOAuth2AuthorizationRequestRepository cookieRepo;
    private final String postLoginRedirect;
    private final String cookieName;
    private final int maxAgeSeconds;
    private final boolean cookieSecure;
    private final String sameSite; // "Lax" | "None" | "Strict"

    public OAuth2AuthenticationSuccessHandler(
            JwtService jwtService,
            RedisTokenStore tokenStore,
            HttpCookieOAuth2AuthorizationRequestRepository cookieRepo,
            @Value("${app.oauth2.post-login-redirect}") String postLoginRedirect,
            @Value("${app.jwt.cookie-name:ACCESS_TOKEN}") String cookieName,
            @Value("${app.jwt.expires-minutes:60}") long expiresMinutes,
            @Value("${app.cookie.secure:false}") boolean cookieSecure,
            @Value("${app.cookie.same-site:Lax}") String sameSite
    ) {
        this.jwtService = jwtService;
        this.tokenStore = tokenStore;
        this.cookieRepo = cookieRepo;
        this.postLoginRedirect = postLoginRedirect;
        this.cookieName = cookieName;
        this.maxAgeSeconds = (int) (expiresMinutes * 60);
        this.cookieSecure = cookieSecure;
        this.sameSite = sameSite;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        OAuth2User principal = (OAuth2User) authentication.getPrincipal();
        String uid   = String.valueOf(principal.getAttributes().get("app_user_id"));
        String email = (String) principal.getAttributes().get("email");

        String jti = jwtService.newJti();
        tokenStore.put(jti, uid);

        String jwt = jwtService.create(uid, jti, Map.of("email", email));

        // bersihkan cookie state oauth2
        cookieRepo.removeAuthorizationRequestCookies(request, response);

        // set JWT di HttpOnly cookie
        CookieUtil.addCookie(response, cookieName, jwt, maxAgeSeconds, "/", true, cookieSecure, sameSite);

        // redirect bersih tanpa token
        String target = UriComponentsBuilder.fromUriString(postLoginRedirect).build(true).toUriString();
        response.sendRedirect(target);
    }
}

