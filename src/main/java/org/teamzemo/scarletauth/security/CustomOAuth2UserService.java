package org.teamzemo.scarletauth.security;

import org.teamzemo.scarletauth.entity.OAuth2Account;
import org.teamzemo.scarletauth.entity.User;
import org.teamzemo.scarletauth.repository.OAuth2AccountRepository;
import org.teamzemo.scarletauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final org.teamzemo.scarletauth.client.UserServiceClient userServiceClient;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId();
        String providerUserId = oAuth2User.getAttribute("sub");
        String email = oAuth2User.getAttribute("email");
        String fullName = oAuth2User.getAttribute("name");

        log.info("OAuth2 (standard) login: provider={}, email={}", provider, email);

        if (email == null) {
            throw new OAuth2AuthenticationException("Email not provided by OAuth2 provider");
        }

        if (!oAuth2AccountRepository.existsByProviderAndProviderUserId(provider, providerUserId)) {
            String tempFirstName = "";
            String tempLastName = "";
            if (fullName != null && !fullName.isBlank()) {
                String[] parts = fullName.trim().split("\\s+", 2);
                tempFirstName = parts[0];
                tempLastName = parts.length > 1 ? parts[1] : "";
            }
            if (tempFirstName.isEmpty()) {
                tempFirstName = email.split("@")[0];
            }
            final String finalFirstName = tempFirstName;
            final String finalLastName = tempLastName;

            User user = userRepository.findByEmail(email)
                    .map(existingUser -> {
                        if (!existingUser.isEmailVerified()) {
                            existingUser.setEmailVerified(true);
                            return userRepository.save(existingUser);
                        }
                        return existingUser;
                    })
                    .orElseGet(() -> {
                        log.info("Creating new user for OAuth2 email: {}", email);
                        return userRepository.save(
                                User.builder()
                                        .email(email)
                                        .firstName(finalFirstName)
                                        .lastName(finalLastName)
                                        .role("ROLE_USER")
                                        .emailVerified(true)
                                        .build()
                        );
                    });

            // Sync user to scarlet-user downstream
            try {
                userServiceClient.syncUser(new org.teamzemo.scarletauth.dto.UserSyncRequest(
                        user.getId(),
                        user.getEmail(),
                        user.getFirstName(),
                        user.getLastName()
                ));
            } catch (Exception e) {
                log.error("Failed to sync OAuth2 user to user service", e);
                throw new OAuth2AuthenticationException("Failed to sync OAuth2 user downstream: " + e.getMessage());
            }

            OAuth2Account oAuth2Account = OAuth2Account.builder()
                    .user(user)
                    .provider(provider)
                    .providerUserId(providerUserId)
                    .build();
            oAuth2AccountRepository.save(oAuth2Account);
            log.info("Linked {} account to user: {}", provider, email);
        }

        return oAuth2User;
    }
}
