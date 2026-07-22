package at.ahmad.auth_project.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JwtService {

    private final String secretKey;
    private final long accessExpirationMs;

    public JwtService(
            @Value("${jwt.access-secret-key}")
            String secretKey,

            @Value("${jwt.access-expiration-ms}")
            long accessExpirationMs
    ) {
        this.secretKey = secretKey;
        this.accessExpirationMs = accessExpirationMs;
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(
            String username,
            String role,
            Set<String> permissions
    ) {
        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .claim("permissions", permissions)
                .issuedAt(new Date())
                .expiration(new Date(
                        System.currentTimeMillis() + accessExpirationMs
                ))
                .signWith(getSigningKey())
                .compact();
    }

    public String extractUsername(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public String extractRole(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role", String.class);
    }

    public Set<String> extractPermissions(String token) {

        List<?> permissions = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("permissions", List.class);

        if (permissions == null) {
            return Collections.emptySet();
        }

        return permissions.stream()
                .map(String::valueOf)
                .collect(Collectors.toSet());
    }

    public boolean isTokenValid(String token) {
        return !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        Date expiration = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();
        return expiration.before(new Date());
    }
}
