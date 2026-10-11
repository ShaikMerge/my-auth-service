package com.shaik.my_auth_server.security;

import com.shaik.my_auth_server.entity.enums.AuthProviderType;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
public class AuthService {




    public AuthProviderType getAuthProviderType(String regestrationId) {

        return switch (regestrationId.toLowerCase()) {
            case "google" -> AuthProviderType.GOOGLE;
            case "github" -> AuthProviderType.GITHUB;
            default -> throw new IllegalArgumentException("Unsupported registrationId: " + regestrationId);
        };

    }


}
