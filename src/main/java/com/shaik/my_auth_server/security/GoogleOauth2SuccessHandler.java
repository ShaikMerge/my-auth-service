
package com.shaik.my_auth_server.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shaik.my_auth_server.entity.User;
import com.shaik.my_auth_server.entity.enums.AuthProviderType;
import com.shaik.my_auth_server.repository.UserRepository;
import com.shaik.my_auth_server.util.AuthUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class GoogleOauth2SuccessHandler
        implements AuthenticationSuccessHandler {

    private final AuthService authService;
    private final AuthUtil authUtil;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication)
            throws IOException, ServletException {

        OAuth2AuthenticationToken oauthToken =
                (OAuth2AuthenticationToken) authentication;

        OAuth2User oauthUser = oauthToken.getPrincipal();

        String registrationId =
                oauthToken.getAuthorizedClientRegistrationId();

        AuthProviderType providerType =
                authService.getAuthProviderType(registrationId);

        String providerId =
                authUtil.getProviderId(oauthUser, registrationId);

        String username =
                authUtil.determineUsername(
                        oauthUser,
                        registrationId,
                        providerId
                );

        User user = userRepository
                .findByProviderIdAndProviderType(
                        providerId,
                        providerType
                )
                .orElse(null);

        boolean newUser = user == null;

        if (newUser) {
            user = User.builder()
                    .username(username)
                    .password(null)
                    .providerId(providerId)
                    .providerType(providerType)
                    .build();
        } else {
            user.setUsername(username);
        }

        user = userRepository.save(user);

        log.info(
                "OAuth2 login successful. userId={}, provider={}, newUser={}",
                user.getId(),
                providerType,
                newUser
        );

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("message", "OAuth2 login successful");
        result.put("userId", user.getId());
        result.put("username", user.getUsername());
        result.put("provider", providerType.name());
        result.put("newUser", newUser);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        objectMapper.writeValue(response.getWriter(), result);
    }
}
