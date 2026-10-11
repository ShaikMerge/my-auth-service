package com.shaik.my_auth_server.util;

import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
public class AuthUtil {

    public String getProviderId(
            OAuth2User oauth2User,
            String registrationId) {

        return switch (registrationId.toLowerCase(Locale.ROOT)) {
            case "google" -> {
                String sub = oauth2User.getAttribute("sub");

                if (sub == null || sub.isBlank()) {
                    throw new IllegalStateException(
                            "Google user ID (sub) is missing"
                    );
                }

                yield sub;
            }

            case "github" -> {
                Object id = oauth2User.getAttribute("id");

                if (id == null) {
                    throw new IllegalStateException(
                            "GitHub user ID is missing"
                    );
                }

                yield String.valueOf(id);
            }

            default -> throw new IllegalArgumentException(
                    "Unsupported registrationId: " + registrationId
            );
        };
    }

    public String determineUsername(
            OAuth2User oauth2User,
            String registrationId,
            String providerId) {

        String email = oauth2User.getAttribute("email");

        if (email != null && !email.isBlank()) {
            return email;
        }

        return switch (registrationId.toLowerCase(Locale.ROOT)) {
            case "google" -> providerId;
            case "github" -> {
                String login = oauth2User.getAttribute("login");

                yield login != null && !login.isBlank()
                        ? login
                        : providerId;
            }
            default -> providerId;
        };
    }
}