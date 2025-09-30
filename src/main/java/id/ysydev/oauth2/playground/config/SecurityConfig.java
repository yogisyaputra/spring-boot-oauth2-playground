package id.ysydev.oauth2.playground.config;

import id.ysydev.oauth2.playground.security.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            CustomOAuth2UserService customOAuth2UserService,
                                            CustomOidcUserService customOidcUserService,
                                            HttpCookieOAuth2AuthorizationRequestRepository cookieRepo,
                                            OAuth2AuthenticationSuccessHandler successHandler,
                                            JwtService jwtService,
                                            RedisTokenStore tokenStore,
                                            @Value("${app.jwt.cookie-name:ACCESS_TOKEN}") String cookieName) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> {}) // siapkan CorsConfigurationSource jika FE beda origin
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/index.html", "/error", "/oauth2/**", "/login**", "/profile.html").permitAll()
                        .requestMatchers("/api/public/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth -> oauth
                        .authorizationEndpoint(ae -> ae.authorizationRequestRepository(cookieRepo))
                        .userInfoEndpoint(ue -> ue
                                .userService(customOAuth2UserService)      // GitHub
                                .oidcUserService(customOidcUserService)    // Google
                        )
                        .successHandler(successHandler)
                )
                .addFilterBefore(new JwtAuthenticationFilter(jwtService, tokenStore, cookieName),
                        UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, e) -> res.sendError(401)));

        return http.build();
    }

}
