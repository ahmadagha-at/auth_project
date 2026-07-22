package at.ahmad.auth_project.dto;

public record AuthTokenResponse(
        String message,
        String accessToken,
        String refreshToken
) {
}
