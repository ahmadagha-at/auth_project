package at.ahmad.auth_project.service;

import at.ahmad.auth_project.dto.RegisterAndLoginRequestDto;
import at.ahmad.auth_project.entities.UserEntity;
import at.ahmad.auth_project.enums.AuthProvider;
import at.ahmad.auth_project.exception.UserNotFoundException;
import at.ahmad.auth_project.repo.UserRepo;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;


@Service
public class UserService implements UserDetailsService {

    private final UserRepo userRepo;

    public UserService(UserRepo userRepo){
        this.userRepo = userRepo;
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

    public void deleteUser(Long id) {

        if (!userRepo.existsById(id)) {
            throw new UserNotFoundException("User not found");
        }

        userRepo.deleteById(id);
    }

    public void updateRole(Long id, String role) {

        if (!role.equals("ROLE_USER") &&
                !role.equals("ROLE_ADMIN")) {
            throw new IllegalArgumentException("Invalid role");
        }

        UserEntity user = userRepo.findById(id)
                .orElseThrow(() ->
                        new UserNotFoundException("User not found")
                );
        user.setRole(role);
        userRepo.save(user);
    }
}
