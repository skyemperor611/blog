package com.blog.my.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@RequiredArgsConstructor
@Configuration
public class WebSecurityConfig {

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
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(new MvcRequestMatcher(introspector, "/login")).permitAll()
                        .requestMatchers(new MvcRequestMatcher(introspector, "/signup")).permitAll()
                        .requestMatchers(new MvcRequestMatcher(introspector, "/user")).permitAll()
                        .anyRequest().authenticated())
                .formLogin((formLogin) ->
                        formLogin
                        .loginPage("/login")
                        .failureUrl("/authentication/login?failed")
                        .loginProcessingUrl("/login")
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .defaultSuccessUrl("/articles", true))
                .logout((logOutConfig) ->
                        logOutConfig.logoutSuccessUrl("/login"));

            return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
