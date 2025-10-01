package id.ysydev.oauth2.playground.security;

import id.ysydev.oauth2.playground.redis.RedisTokenStore;
import id.ysydev.oauth2.playground.security.jwt.JwtService;
import id.ysydev.oauth2.playground.user.User;
import id.ysydev.oauth2.playground.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserService userService;
    private final RedisTokenStore tokenStore;
    private final HttpCookieOAuth2AuthorizationRequestRepository cookieRepo;
    private final String postLoginRedirect;
    private final boolean cookieSecure;
    private final String sameSite; // "Lax" | "None" | "Strict"
    private final String accessCookieName;
    private final String refreshCookieName;
    private final int accessMaxAge;
    private final int refreshMaxAge;
    private final String cookieDomain;

    public OAuth2AuthenticationSuccessHandler(
            JwtService jwtService, UserService userService,
            RedisTokenStore tokenStore,
            HttpCookieOAuth2AuthorizationRequestRepository cookieRepo,
            @Value("${app.oauth2.post-login-redirect}") String postLoginRedirect,
            @Value("${app.jwt.access-cookie-name:ACCESS_TOKEN}") String accessCookieName,
            @Value("${app.jwt.refresh-cookie-name:REFRESH_TOKEN}") String refreshCookieName,
            @Value("${app.jwt.access-expires-minutes:15}") long accessMinutes,
            @Value("${app.jwt.refresh-expires-days:14}") long refreshDays,
            @Value("${app.cookie.secure:false}") boolean cookieSecure,
            @Value("${app.cookie.same-site:Lax}") String sameSite,
            @Value("${app.cookie.domain:}") String cookieDomain
    ) {
        this.jwtService = jwtService;
        this.userService = userService;
        this.tokenStore = tokenStore;
        this.cookieRepo = cookieRepo;
        this.postLoginRedirect = postLoginRedirect;
        this.accessCookieName = accessCookieName;
        this.refreshCookieName = refreshCookieName;
        this.accessMaxAge = (int)(accessMinutes * 60);
        this.refreshMaxAge = (int)(refreshDays * 24 * 60 * 60);
        this.cookieSecure = cookieSecure;
        this.sameSite = sameSite;
        this.cookieDomain = cookieDomain;
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res, Authentication auth) throws IOException {
        OAuth2User p = (OAuth2User) auth.getPrincipal();
        String uid = String.valueOf(p.getAttributes().get("app_user_id"));
        String email = (String) p.getAttributes().get("email");
        User user = userService.findById(UUID.fromString(uid)).orElseThrow();

        // buat & simpan ACCESS
        String aJti = jwtService.newJti();

        String accessJwt = jwtService.createAccess(uid, aJti, Map.of(
                "email", email,
                "roles", user.getRole()  // <- penting
        ));
        tokenStore.putAccess(aJti, uid);

        // buat & simpan REFRESH
        String rJti = jwtService.newJti();
        String refresh = jwtService.createRefresh(uid, rJti);
        tokenStore.putRefresh(rJti, uid);

        cookieRepo.removeAuthorizationRequestCookies(req, res);

        // set cookies
        CookieUtil.addCookie(res, accessCookieName, accessJwt, accessMaxAge, "/", true, cookieSecure, sameSite, cookieDomain);
        CookieUtil.addCookie(res, refreshCookieName, refresh, refreshMaxAge, "/", true, cookieSecure, sameSite, cookieDomain);

        res.sendRedirect(postLoginRedirect); // balik ke FE
    }


}

