package at.ahmad.auth_project.controller;

import at.ahmad.auth_project.dto.AuthTokenResponse;
import at.ahmad.auth_project.dto.RefreshTokenRequest;
import at.ahmad.auth_project.entities.RefreshToken;
import at.ahmad.auth_project.entities.UserEntity;
import at.ahmad.auth_project.service.RefreshTokenService;
import at.ahmad.auth_project.dto.RegisterAndLoginRequestDto;
import at.ahmad.auth_project.service.JwtService;
import at.ahmad.auth_project.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/auth")
public class userController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    public userController(
            UserService userService,
            AuthenticationManager authenticationManager,
            JwtService jwtService,
            PasswordEncoder passwordEncoder,
            RefreshTokenService refreshTokenService
    ) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody RegisterAndLoginRequestDto req) {
        String encodedPassword = passwordEncoder.encode(req.getPassword());
        req.setPassword(encodedPassword);
        userService.register(req);
        return ResponseEntity.ok(Map.of("message", "Registration successful"));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthTokenResponse> login(
            @Valid @RequestBody RegisterAndLoginRequestDto req
    ) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        req.getUsername(),
                        req.getPassword()
                );

        Authentication authentication =
                authenticationManager.authenticate(authenticationToken);

         /* we use jwt
            SecurityContextHolder.getContext().setAuthentication(authentication);

            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
             */

        String role = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .findFirst()
                .orElseThrow(() ->
                        new IllegalStateException(
                                "Authenticated user has no role"
                        )
                );

        Set<String> permissions = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> !authority.startsWith("ROLE_"))
                .collect(Collectors.toSet());

        String accessToken = jwtService.generateToken(
                authentication.getName(),
                role,
                permissions
        );

        RefreshToken refreshToken =
                refreshTokenService.createOrReplaceRefreshToken(
                        authentication.getName()
                );

        AuthTokenResponse response = new AuthTokenResponse(
                "Login successful",
                accessToken,
                refreshToken.getToken()
        );

        return ResponseEntity.ok(response);
        /*
        ResponseCookie cookie = ResponseCookie.from("jwt", jwtToken)
                .httpOnly(true) // Prevents JavaScript access (helps protect against XSS)
                .path("/")      //  Makes the cookie available for the entire application
                .maxAge(24 * 60 * 60) // Sets the cookie lifetime to one day, in secondsGültigkeit z. B. 1 Tag in Sekunden
                .sameSite("Strict") // Restricts cross-site requests(helps protect against CSRF)
                .build();

        // 3. Cookie in header
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .build();

         */
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthTokenResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        RefreshToken rotatedRefreshToken =
                refreshTokenService.verifyAndRotateRefreshToken(
                        request.refreshToken()
                );

        UserEntity user = rotatedRefreshToken.getUser();

        String newAccessToken = jwtService.generateToken(
                user.getUsername(),
                user.getRole(),
                user.getPermissions()
        );

        AuthTokenResponse response = new AuthTokenResponse(
                "Token refreshed successfully",
                newAccessToken,
                rotatedRefreshToken.getToken()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        refreshTokenService.revokeRefreshToken(
                request.refreshToken()
        );

        return ResponseEntity.ok(
                Map.of("message", "Logout successful")
        );
    }

    @GetMapping("/Dashboard")
    public ResponseEntity<?> dashboard() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("log in first");
        }
        Object principal = auth.getPrincipal();
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        assert principal != null;
        Map<Object, Object> result = Map.of("principal", principal, "authorities", authorities);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/admin-settings")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> adminSettings() {
        return ResponseEntity.ok("admin settings");
    }

    @GetMapping("/profile")
    @PreAuthorize("hasAuthority('PROFILE_READ')")
    public ResponseEntity<?> getProfile(Authentication authentication) {

        String username = authentication.getName();

        return ResponseEntity.ok(
                Map.of("username", username)
        );
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('USER_READ_ALL')")
    public ResponseEntity<?> getAllUsers() {

        return ResponseEntity.ok(
                userService.getAllUsers()
        );
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasAuthority('USER_DELETE')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {

        userService.deleteUser(id);

        return ResponseEntity.ok(
                Map.of("message", "User deleted successfully")
        );
    }

    @PatchMapping("/users/{id}/role")
    @PreAuthorize("hasAuthority('USER_ROLE_UPDATE')")
    public ResponseEntity<?> updateUserRole(
            @PathVariable Long id,
            @RequestBody Map<String, String> request
    ) {
        String role = request.get("role");

        userService.updateRole(id, role);

        return ResponseEntity.ok(
                Map.of("message", "Role updated successfully")
        );
    }
}
