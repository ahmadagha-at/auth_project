package at.ahmad.auth_project.enums;

import lombok.Getter;

import java.util.Set;

@Getter
public enum Role{
    ROLE_USER(
            Set.of(
                    Permission.PROFILE_READ,
                    Permission.PROFILE_UPDATE
            )
    ),
    ROLE_ADMIN(
            Set.of(
                    Permission.USER_DELETE,
                    Permission.USER_ROLE_UPDATE,
                    Permission.USER_READ_ALL,
                    Permission.PROFILE_READ,
                    Permission.PROFILE_UPDATE
            )
    );

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

}
