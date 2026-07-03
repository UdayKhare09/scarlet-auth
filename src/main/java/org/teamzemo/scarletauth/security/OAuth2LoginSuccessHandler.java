package org.teamzemo.scarletauth.security;

import org.teamzemo.scarletauth.config.AppProperties;
import org.teamzemo.scarletauth.entity.User;
import org.teamzemo.scarletauth.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final CookieUtils cookieUtils;
    private final UserRepository userRepository;
    private final AppProperties appProperties;
    private final org.teamzemo.scarletauth.service.SessionService sessionService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        Object principal = authentication.getPrincipal();

        String email;
        if (principal instanceof OidcUser oidcUser) {
            email = oidcUser.getEmail();
        } else if (principal instanceof OAuth2User oAuth2User) {
            email = (String) oAuth2User.getAttributes().get("email");
        } else {
            log.error("Unexpected principal type: {}", principal.getClass());
            response.sendRedirect(appProperties.getWebauthn().getRpOrigin() + "/login?error=oauth");
            return;
        }

        if (email == null) {
            log.error("No email found in OAuth2 principal");
            response.sendRedirect(appProperties.getWebauthn().getRpOrigin() + "/login?error=no_email");
            return;
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found after OAuth2 login"));

        String accessToken = jwtService.generateAccessToken(email, user.getId(), user.getFirstName(), user.getLastName(), user.getRole());
        sessionService.createSession(user, request, response);

        cookieUtils.setAccessTokenCookie(response, accessToken);

        log.info("OAuth2 login success for user: {}", email);

        response.sendRedirect(appProperties.getWebauthn().getRpOrigin() + "/dashboard");
    }
}
