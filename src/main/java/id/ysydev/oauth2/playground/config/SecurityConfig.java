package id.ysydev.oauth2.playground.config;

import id.ysydev.oauth2.playground.redis.RedisTokenStore;
import id.ysydev.oauth2.playground.security.*;
import id.ysydev.oauth2.playground.security.github.CustomOAuth2UserService;
import id.ysydev.oauth2.playground.security.gmail.CustomOidcUserService;
import id.ysydev.oauth2.playground.security.jwt.JwtAuthenticationFilter;
import id.ysydev.oauth2.playground.security.jwt.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {

    /**
     * CORS: atur origin FE di sini.
     * Dev (FE di 8181): http://localhost:8181
     * Prod: ganti ke https://app.example.com
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.allowed-origins:http://localhost:8181}") String allowedOriginsCsv) {

        CorsConfiguration cfg = new CorsConfiguration();
        // Bisa multi-origin via CSV: "http://localhost:8181,https://app.example.com"
        cfg.setAllowedOrigins(List.of(allowedOriginsCsv.split("\\s*,\\s*")));
        cfg.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
        cfg.setAllowedHeaders(List.of("Content-Type","Accept","Authorization","X-Requested-With"));
        cfg.setAllowCredentials(true); // wajib kalau kirim cookie HttpOnly cross-origin
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            CustomOAuth2UserService customOAuth2UserService,          // untuk GitHub (OAuth2)
            CustomOidcUserService customOidcUserService,              // untuk Google (OIDC)
            HttpCookieOAuth2AuthorizationRequestRepository cookieRepo,
            OAuth2AuthenticationSuccessHandler successHandler,
            JwtService jwtService,
            RedisTokenStore tokenStore,
            @Value("${app.jwt.access-cookie-name:ACCESS_TOKEN}") String accessCookieName
    ) throws Exception {

        http
                // App ini 100% stateless (JWT di cookie)
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> {}) // pakai bean corsConfigurationSource()
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Authorization rules
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/", "/index.html", "/error",
                                "/oauth2/**", "/login**",
                                "/profile.html"         // halaman FE sederhana (opsional)
                        ).permitAll()
                        .requestMatchers(
                                "/api/public/**",
                                "/api/auth/refresh"     // refresh boleh tanpa auth; cookie akan diverifikasi di controller
                        ).permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )

                // OAuth2 Login (Google/GitHub) tanpa HttpSession: simpan state di cookie
                .oauth2Login(oauth -> oauth
                        .authorizationEndpoint(ae -> ae.authorizationRequestRepository(cookieRepo))
                        .userInfoEndpoint(ue -> ue
                                .userService(customOAuth2UserService)    // GitHub
                                .oidcUserService(customOidcUserService)  // Google
                        )
                        .successHandler(successHandler)            // issue ACCESS/REFRESH cookie + redirect ke FE
                )

                // JWT filter: validasi ACCESS_TOKEN dari cookie + cek whitelist Redis
                .addFilterBefore(
                        new JwtAuthenticationFilter(jwtService, tokenStore, accessCookieName),
                        UsernamePasswordAuthenticationFilter.class
                )

                // Kalau unauthenticated akses endpoint protected → 401
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((req, res, e) -> res.sendError(401))
                );

        return http.build();
    }
}
