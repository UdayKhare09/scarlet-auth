package org.teamzemo.scarletauth.security;

import org.teamzemo.scarletauth.entity.OAuth2Account;
import org.teamzemo.scarletauth.entity.User;
import org.teamzemo.scarletauth.repository.OAuth2AccountRepository;
import org.teamzemo.scarletauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService extends OidcUserService {

    private final UserRepository userRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId();
        String providerUserId = oidcUser.getSubject();
        String email = oidcUser.getEmail();
        String fullName = oidcUser.getFullName();

        log.info("OAuth2 login: provider={}, email={}", provider, email);

        if (!oAuth2AccountRepository.existsByProviderAndProviderUserId(provider, providerUserId)) {
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
                                        .fullName(fullName)
                                        .role("ROLE_USER")
                                        .emailVerified(true)
                                        .build()
                        );
                    });

            OAuth2Account oAuth2Account = OAuth2Account.builder()
                    .user(user)
                    .provider(provider)
                    .providerUserId(providerUserId)
                    .build();
            oAuth2AccountRepository.save(oAuth2Account);
            log.info("Linked {} account to user: {}", provider, email);
        }

        return oidcUser;
    }
}
