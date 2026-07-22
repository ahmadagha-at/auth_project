package at.ahmad.auth_project.service;

import at.ahmad.auth_project.entities.UserEntity;
import at.ahmad.auth_project.enums.AuthProvider;
import at.ahmad.auth_project.repo.UserRepo;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CustomOidcUserService extends OidcUserService {

    private final UserRepo userRepo;

    public CustomOidcUserService(UserRepo userRepo) {
        this.userRepo = userRepo;
    }

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest)
            throws OAuth2AuthenticationException {

        OidcUser oidcUser = super.loadUser(userRequest);

        String googleId = oidcUser.getSubject();
        String email = oidcUser.getEmail();
        Boolean emailVerified = oidcUser.getEmailVerified();

        if (googleId == null || googleId.isBlank()) {
            throw oauthError(
                    "google_id_missing",
                    "Google account has no subject identifier"
            );
        }

        if (email == null || email.isBlank()) {
            throw oauthError(
                    "email_missing",
                    "Google account has no email address"
            );
        }

        if (!Boolean.TRUE.equals(emailVerified)) {
            throw oauthError(
                    "email_not_verified",
                    "Google email address is not verified"
            );
        }

        if (userRepo.findByProviderAndProviderId(
                AuthProvider.GOOGLE,
                googleId
        ).isPresent()) {
            return oidcUser;
        }


        UserEntity existingUser = userRepo.findByUsername(email);

        if (existingUser != null) {
            throw oauthError(
                    "account_already_exists",
                    "An account with this email already exists"
            );
        }

        UserEntity googleUser = UserEntity.createGoogleUser(
                email,
                googleId
        );

        userRepo.save(googleUser);

        return oidcUser;
    }

    private OAuth2AuthenticationException oauthError(
            String code,
            String description
    ) {
        OAuth2Error error = new OAuth2Error(
                code,
                description,
                null
        );

        return new OAuth2AuthenticationException(error);
    }
}
