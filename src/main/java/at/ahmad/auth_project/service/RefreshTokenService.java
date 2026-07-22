package at.ahmad.auth_project.service;

import at.ahmad.auth_project.entities.RefreshToken;
import at.ahmad.auth_project.entities.UserEntity;
import at.ahmad.auth_project.exception.CompromisedTokenException;
import at.ahmad.auth_project.exception.RefreshTokenException;
import at.ahmad.auth_project.exception.UserNotFoundException;
import at.ahmad.auth_project.repo.RefreshTokenRepo;
import at.ahmad.auth_project.repo.UserRepo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final long refreshTokenDurationMs;
    private final RefreshTokenRepo refreshTokenRepository;
    private final UserRepo userRepository;

    public RefreshTokenService(
            RefreshTokenRepo refreshTokenRepository,
            UserRepo userRepository,
            @Value("${jwt.refresh-expiration-ms}")
            long refreshTokenDurationMs
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.refreshTokenDurationMs = refreshTokenDurationMs;
    }

    @Transactional
    public RefreshToken createOrReplaceRefreshToken(String username) {

        UserEntity user = userRepository.findByUsername(username);

        if (user == null) {
            throw new UserNotFoundException("User not found");
        }

        refreshTokenRepository.deleteAllByUser(user);
        refreshTokenRepository.flush();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(generateRefreshToken());
        refreshToken.setExpiryDate(calculateExpiryDate());
        refreshToken.setUsed(false);
        refreshToken.setFamilyId(UUID.randomUUID().toString());

        return refreshTokenRepository.saveAndFlush(refreshToken);
    }


    @Transactional(
            noRollbackFor = {
                    RefreshTokenException.class,
                    CompromisedTokenException.class
            }
    )
    public RefreshToken verifyAndRotateRefreshToken(
            String refreshTokenValue
    ) {
        RefreshToken refreshToken = refreshTokenRepository
                .findByToken(refreshTokenValue)
                .orElseThrow(() ->
                        new RefreshTokenException(
                                "Refresh token is invalid"
                        )
                );
        if (refreshToken.isUsed()) {

            refreshTokenRepository.deleteAllByFamilyId(refreshToken.getFamilyId());
            refreshTokenRepository.flush();

            throw new CompromisedTokenException(
                    "Security Alert: Suspected Token Theft! You have been logged out everywhere."
            );
        }

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);

            throw new RefreshTokenException(
                    "Refresh token has expired. Please log in again"
            );
        }

        refreshToken.setUsed(true);
        refreshTokenRepository.save(refreshToken);

        RefreshToken newToken = new RefreshToken();
        newToken.setToken(generateRefreshToken());
        newToken.setUser(refreshToken.getUser());
        newToken.setFamilyId(refreshToken.getFamilyId());
        newToken.setExpiryDate(calculateExpiryDate());
        newToken.setUsed(false);

        return refreshTokenRepository.save(newToken);
    }

    @Transactional
    public void revokeRefreshToken(String refreshTokenValue) {
        refreshTokenRepository.deleteByToken(refreshTokenValue);
    }

    private String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }

    private Instant calculateExpiryDate() {
        return Instant.now().plusMillis(refreshTokenDurationMs);
    }
}
