package com.blog.my.config;

import com.blog.my.config.jwt.TokenProvider;
import com.blog.my.config.oauth.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.blog.my.config.oauth.OAuth2SuccessHandler;
import com.blog.my.config.oauth.Oauth2UserCustomeService;
import com.blog.my.repository.RefreshTokenRepository;
import com.blog.my.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@RequiredArgsConstructor
@Configuration
public class WebOAuthSecurityConfig {

    private final Oauth2UserCustomeService oauth2UserCustomeService;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService userService;
    @Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring()
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**"))
                .requestMatchers(new AntPathRequestMatcher( "/favicon.ico"))
                .requestMatchers(new AntPathRequestMatcher( "/css/**"))
                .requestMatchers(new AntPathRequestMatcher( "/js/**"))
                .requestMatchers(new AntPathRequestMatcher( "/img/**"))
                .requestMatchers(new AntPathRequestMatcher( "/lib/**"));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
            http
                    .csrf((csrfConfig) ->
                            csrfConfig.disable())
                    .formLogin((formLoginConfig) ->
                            formLoginConfig.disable())
                    .logout((logOutConfig) ->
                            logOutConfig.disable());

            http
                    .sessionManagement((sessionManagementConfig) ->
                    sessionManagementConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

            http
                    .addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

            http
                        .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(new MvcRequestMatcher(introspector, "/login")).permitAll()
                        .requestMatchers(new MvcRequestMatcher(introspector, "/signup")).permitAll()
                        .requestMatchers(new MvcRequestMatcher(introspector, "/user")).permitAll()
                        .anyRequest().authenticated());

            http
                    .oauth2Login((oauth2LoginConfig) ->
                            oauth2LoginConfig.loginPage("/login")
                                    .authorizationEndpoint((authorizationEndpointConfig ->
                                            authorizationEndpointConfig
                                                    .authorizationRequestRepository(
                                                            oAuth2AuthorizationRequestBasedOnCookieRepository())))
                                    .successHandler(oAuth2SuccessHandler())
                                    .userInfoEndpoint(userInfoEndpointConfig ->
                                            userInfoEndpointConfig
                                                    .userService(oauth2UserCustomeService)));

            http
                    .logout((logoutConfig) ->
                            logoutConfig
                                    .logoutSuccessUrl("/login"));

            http
                    .exceptionHandling((exceptionHandlingConfig) ->
                            exceptionHandlingConfig
                                    .defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                            new AntPathRequestMatcher("/api/**")));

            return http.build();
    }

    @Bean
    public OAuth2SuccessHandler oAuth2SuccessHandler() {
        return new OAuth2SuccessHandler(tokenProvider,
                refreshTokenRepository,
                oAuth2AuthorizationRequestBasedOnCookieRepository(),
                userService);
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(tokenProvider);
    }

    @Bean
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
