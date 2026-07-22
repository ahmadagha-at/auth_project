package at.ahmad.auth_project.service;

import at.ahmad.auth_project.dto.RegisterAndLoginRequestDto;
import at.ahmad.auth_project.entities.UserEntity;
import at.ahmad.auth_project.enums.AuthProvider;
import at.ahmad.auth_project.enums.Role;
import at.ahmad.auth_project.exception.UserNotFoundException;
import at.ahmad.auth_project.repo.RefreshTokenRepo;
import at.ahmad.auth_project.repo.UserRepo;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;


@Service
public class UserService implements UserDetailsService {

    private final UserRepo userRepo;
    private final RefreshTokenRepo refreshTokenRepo;

    public UserService(
            UserRepo userRepo,
            RefreshTokenRepo refreshTokenRepo
    ) {
        this.userRepo = userRepo;
        this.refreshTokenRepo = refreshTokenRepo;
    }

    public void register(RegisterAndLoginRequestDto userDto){
        UserEntity user = new UserEntity(userDto.getUsername(),
                userDto.getPassword());

        userRepo.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(
            String username
    ) throws UsernameNotFoundException {

        UserEntity user = userRepo.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }

        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new UsernameNotFoundException(
                    "This account uses Google login"
            );
        }

        if (user.getPassword() == null) {
            throw new UsernameNotFoundException(
                    "Local password is missing"
            );
        }

        List<SimpleGrantedAuthority> authorities =
                user.getPermissions()
                        .stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toCollection(ArrayList::new));

        authorities.add(
                new SimpleGrantedAuthority(user.getRole())
        );

        return new User(
                user.getUsername(),
                user.getPassword(),
                authorities
        );
    }

    public List<UserEntity> getAllUsers() {
        return userRepo.findAll();
    }

    @Transactional
    public void deleteUser(Long id) {
        UserEntity user = userRepo.findById(id)
                .orElseThrow(() ->
                        new UserNotFoundException("User not found")
                );

        refreshTokenRepo.deleteAllByUser(user);
        refreshTokenRepo.flush();
        userRepo.delete(user);
    }

    public void updateRole(Long id, String roleName) {
        Role role;

        try {
            role = Role.valueOf(roleName);
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new IllegalArgumentException("Invalid role");
        }

        UserEntity user = userRepo.findById(id)
                .orElseThrow(() ->
                        new UserNotFoundException("User not found")
                );
        user.setRole(role.name());
        user.setPermissions(
                role.getPermissions()
                        .stream()
                        .map(Enum::name)
                        .collect(Collectors.toSet())
        );
        userRepo.save(user);
    }
}
