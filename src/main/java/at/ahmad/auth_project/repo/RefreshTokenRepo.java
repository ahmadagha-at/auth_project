package at.ahmad.auth_project.repo;

import at.ahmad.auth_project.entities.RefreshToken;
import at.ahmad.auth_project.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUser(UserEntity user);

    void deleteByToken(String token);

    void deleteAllByFamilyId(String familyId);

    void deleteAllByUser(UserEntity user);
}
