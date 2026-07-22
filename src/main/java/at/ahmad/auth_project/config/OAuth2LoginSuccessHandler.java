package at.ahmad.auth_project.config;
import at.ahmad.auth_project.dto.AuthTokenResponse;
import at.ahmad.auth_project.entities.RefreshToken;
import at.ahmad.auth_project.entities.UserEntity;
import at.ahmad.auth_project.enums.AuthProvider;
import at.ahmad.auth_project.repo.UserRepo;
import at.ahmad.auth_project.service.JwtService;
import at.ahmad.auth_project.service.RefreshTokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

@Component
public class OAuth2LoginSuccessHandler
        extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepo userRepo;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final ObjectMapper objectMapper;

    public OAuth2LoginSuccessHandler(
            UserRepo userRepo,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            ObjectMapper objectMapper
    ) {
        this.userRepo = userRepo;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        OidcUser oidcUser =
                (OidcUser) authentication.getPrincipal();

        String googleId = oidcUser.getSubject();

        UserEntity user = userRepo
                .findByProviderAndProviderId(
                        AuthProvider.GOOGLE,
                        googleId
                )
                .orElseThrow(() ->
                        new IllegalStateException(
                                "Google user was not saved"
                        )
                );

        String accessToken = jwtService.generateToken(
                user.getUsername(),
                user.getRole(),
                user.getPermissions()
        );

        RefreshToken refreshToken =
                refreshTokenService.createOrReplaceRefreshToken(
                        user.getUsername()
                );

        AuthTokenResponse tokenResponse =
                new AuthTokenResponse(
                        "Google login successful",
                        accessToken,
                        refreshToken.getToken()
                );

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(
                MediaType.APPLICATION_JSON_VALUE
        );
        response.setCharacterEncoding("UTF-8");

        objectMapper.writeValue(
                response.getWriter(),
                tokenResponse
        );
    }
}
