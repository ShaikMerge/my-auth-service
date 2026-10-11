package com.shaik.my_auth_server.configuration;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.UUID;

@Configuration
public class RegisteredClientConifg {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {

        return  new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public ApplicationRunner registerWebClient(
            RegisteredClientRepository repository,
            PasswordEncoder clientPasswordEncoder) {

        return args -> {
            String clientId = "my-web-client";

            // Avoid inserting the same client on every restart.
            if (repository.findByClientId(clientId) != null) {
                System.out.println(
                        "Client already registered: " + clientId);
                return;
            }

            String rawSecret = "shaik-secret";

            if (rawSecret == null || rawSecret.isBlank()) {
                throw new IllegalStateException(
                        "Set the MY_WEB_CLIENT_SECRET environment variable");
            }

            RegisteredClient client =
                    RegisteredClient.withId(UUID.randomUUID().toString())
                            .clientId(clientId)
                            .clientName("My Web Application")
                            .clientSecret(
                                    clientPasswordEncoder.encode(rawSecret))
                            .clientAuthenticationMethod(
                                    ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .authorizationGrantType(
                                    AuthorizationGrantType.AUTHORIZATION_CODE)
                            .redirectUri(
                                    "http://127.0.0.1:8081/callback")
                            .scope("profile")
                            .build();

            repository.save(client);

            System.out.println(
                    "Successfully registered client: " + clientId);
        };
    }
}
