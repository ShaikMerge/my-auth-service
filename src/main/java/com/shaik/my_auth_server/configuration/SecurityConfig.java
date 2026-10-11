package com.shaik.my_auth_server.configuration;

import com.shaik.my_auth_server.security.GoogleOauth2SuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
@Slf4j
@RequiredArgsConstructor
public class SecurityConfig {

    private final GoogleOauth2SuccessHandler googleOauth2SuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth -> oauth
                        .successHandler(googleOauth2SuccessHandler)
                        .failureHandler((request, response, exception) -> {
                            log.error(
                                    "OAuth2 login failed",
                                    exception
                            );

                            response.sendError(
                                    HttpStatus.UNAUTHORIZED.value(),
                                    "OAuth2 login failed"
                            );
                        })
                );

        return http.build();
    }
}
