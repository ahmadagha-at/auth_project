package at.ahmad.auth_project.repo;

import at.ahmad.auth_project.entities.UserEntity;
import at.ahmad.auth_project.enums.AuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepo extends JpaRepository<UserEntity, Long> {
    UserEntity findByUsername(String username);

    Optional<UserEntity> findByProviderAndProviderId(
            AuthProvider provider,
            String providerId
    );

}
