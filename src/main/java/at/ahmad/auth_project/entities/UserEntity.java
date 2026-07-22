package at.ahmad.auth_project.entities;

import at.ahmad.auth_project.enums.AuthProvider;
import at.ahmad.auth_project.enums.Role;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


@Getter
@Entity
@Table(name = "users")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @Column
    private String password;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    @Setter
    private String role;

    @Setter
    private Set<String> permissions;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AuthProvider provider;

    @Column(name = "provider_id")
    private String providerId;

    protected UserEntity() {
    }

    public UserEntity(String username, String password) {
        this.username = username;
        this.password = password;
        this.provider = AuthProvider.LOCAL;
        this.providerId = null;

        assignDefaultRole(username);
    }

    public static UserEntity createGoogleUser(
            String email,
            String googleId
    ) {
        UserEntity user = new UserEntity();

        user.username = email;
        user.password = null;
        user.provider = AuthProvider.GOOGLE;
        user.providerId = googleId;
        user.assignDefaultRole(email);

        return user;
    }

    private void assignDefaultRole(String username) {
        if ("chef".equals(username)) {
            this.role = Role.ROLE_ADMIN.name();
            this.permissions = Role.ROLE_ADMIN
                    .getPermissions()
                    .stream()
                    .map(Enum::name)
                    .collect(Collectors.toSet());
        } else {
            this.role = Role.ROLE_USER.name();
            this.permissions = Role.ROLE_USER
                    .getPermissions()
                    .stream()
                    .map(Enum::name)
                    .collect(Collectors.toSet());
        }
    }
}
