package com.mzhn.chemp.auth.utils.jwt;

import com.mzhn.chemp.auth.dto.auth.UserClaims;
import com.mzhn.chemp.auth.domain.ERole;
import com.mzhn.chemp.auth.domain.Role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Data
@Slf4j
public class JwtService {
    @Value("${spring.jwt.accessTokenTTL}")
    public int jwtAccessTokenTTL;

    @Value("${spring.jwt.refreshTokenTTL}")
    public int jwtRefreshTokenTTL;
    private final SecretKey jwtAccessSecret;
    private final SecretKey jwtRefreshSecret;

    public JwtService(
            @Value("${spring.jwt.accessToken}") String jwtAccessSecret,
            @Value("${spring.jwt.refreshToken}") String jwtRefreshSecret
    ) {
        this.jwtAccessSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtAccessSecret));
        this.jwtRefreshSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtRefreshSecret));
    }

    public String generateAccessToken(UserClaims user) {
        return generateJwtToken(jwtAccessSecret, jwtAccessTokenTTL, user);
    }

    public boolean verifyAccessToken(String token) {
        return validateJwtToken(jwtAccessSecret, token);
    }

    public String generateRefreshToken(UserClaims user) {
        return generateJwtToken(jwtRefreshSecret, jwtRefreshTokenTTL, user);
    }

    public boolean verifyRefreshToken(String token) {
        return validateJwtToken(jwtRefreshSecret, token);
    }

    public Claims getAccessClaims(@NotNull String token) {
        return getClaims(token, jwtAccessSecret);
    }

    public Claims getRefreshClaims(@NotNull String token) {
        return getClaims(token, jwtRefreshSecret);
    }

    private Claims getClaims(@NotNull String token, @NotNull SecretKey secret) {
        return Jwts.parser()
                .verifyWith(secret)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private String generateJwtToken(SecretKey key, int ttl, UserClaims user) {
        final LocalDateTime now = LocalDateTime.now();
        final Instant expirationInstant = now.plusMinutes(ttl).atZone(ZoneId.systemDefault()).toInstant();
        final Date expiration = Date.from(expirationInstant);

        return Jwts.builder()
                .subject(user.getEmail())
                .claims(generateClaims(user))
                .issuedAt(new Date())
                .expiration(expiration)
                .signWith(key)
                .compact();
    }

    private boolean validateJwtToken(@NotNull SecretKey secret, @NotNull String token) {
        try {
            Jwts.parser().verifyWith(secret).build().parseSignedClaims(token);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    private Claims generateClaims(UserClaims user) {
        return Jwts.claims()
                .add("id", user.getId())
                .add("email", user.getEmail())
                .add("roles", user.getRoles())
                .build();
    }

    private void test() {
        /*
        Claims claims = Jwts.parser().verifyWith(secret).build().parseSignedClaims(token).getPayload();
        List<Object> rolesList = (List<Object>) claims.get("roles");
        Set<Role> roles = (Set<Role>) rolesList.stream()
                .map(roleObj -> {
                    var roleMap = (Map<String, Object>) roleObj;
                    int id = (int) roleMap.get("id");
                    String name = (String) roleMap.get("name");
                    return new Role(id, ERole.valueOf(name));
                }).collect(Collectors.toSet());

        return new UserClaims(UUID.fromString(claims.get("id", String.class)), claims.get("email", String.class), roles);
         */
    }
}
