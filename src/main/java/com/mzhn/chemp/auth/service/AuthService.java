package com.mzhn.chemp.auth.service;

import com.mzhn.chemp.auth.dto.auth.TokensResponse;
import com.mzhn.chemp.auth.dto.auth.SignInRequest;
import com.mzhn.chemp.auth.dto.auth.SignUpRequest;
import com.mzhn.chemp.auth.dto.auth.UserClaims;
import com.mzhn.chemp.auth.domain.ERole;
import com.mzhn.chemp.auth.domain.Role;
import com.mzhn.chemp.auth.domain.User;
import com.mzhn.chemp.auth.exception.ForbiddenAccessException;
import com.mzhn.chemp.auth.exception.RoleNotFoundException;
import com.mzhn.chemp.auth.exception.UserAlreadyExistsException;
import com.mzhn.chemp.auth.exception.UserNotFoundException;
import com.mzhn.chemp.auth.repository.RoleRepository;
import com.mzhn.chemp.auth.repository.UserRepository;
import com.mzhn.chemp.auth.utils.jwt.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;
    private final StringRedisTemplate cacheManager;


    public TokensResponse signUp(SignUpRequest signUpRequest) throws UserAlreadyExistsException {
        log.info("Регистрация пользователя {}", signUpRequest.getEmail());
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new UserAlreadyExistsException(signUpRequest.getEmail());
        }

        // hash password
        String passwordHash = passwordEncoder.encode(signUpRequest.getPassword());

        // get roles
        Set<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByName(ERole.USER)
                .orElseThrow(() -> new RoleNotFoundException(ERole.USER));
        roles.add(userRole);

        User user = new User(signUpRequest.getEmail(), passwordHash, signUpRequest.getFirstName(), signUpRequest.getLastName(), roles);
        userRepository.save(user);

        return signIn(new SignInRequest(signUpRequest.getEmail(), signUpRequest.getPassword()));
    }

    public TokensResponse signIn(@Valid SignInRequest signInRequest) throws UserNotFoundException {
        log.info("Авторизация пользователя {}", signInRequest.getEmail());
        if (!userRepository.existsByEmail(signInRequest.getEmail())) {
            throw new UserNotFoundException(signInRequest.getEmail());
        }

        User user = userRepository.findOneByEmail(signInRequest.getEmail())
                .orElseThrow(() -> new UserNotFoundException(signInRequest.getEmail()));

        if (!passwordEncoder.matches(signInRequest.getPassword(), user.getPasswordHash()))
            throw new UserNotFoundException(signInRequest.getEmail());

        TokensResponse tokensResponse = generateTokens(new UserClaims(user.getId(), user.getEmail(), user.getRoles(), true));
        cacheManager.opsForValue().set(user.getId().toString(), tokensResponse.getRefreshToken(), Duration.ofMinutes(jwtService.getJwtRefreshTokenTTL()));

        return tokensResponse;
    }

    public TokensResponse refreshTokens(String refreshToken) {
        if (!jwtService.verifyRefreshToken(refreshToken))
            throw new ForbiddenAccessException();
        final Claims claims = jwtService.getRefreshClaims(refreshToken);

        String cachedRefreshToken = cacheManager.opsForValue().get(claims.getId());
        if (!refreshToken.equals(cachedRefreshToken)) {
            throw new ForbiddenAccessException();
        }

        final User user = userRepository.findOneByEmail(claims.getSubject())
                .orElseThrow(() -> new UserNotFoundException(claims.getSubject()));

        TokensResponse tokensResponse = generateTokens(new UserClaims(user.getId(), user.getEmail(), user.getRoles(), true));
        cacheManager.opsForValue().set(claims.getId().toString(), tokensResponse.getRefreshToken(), Duration.ofMinutes(jwtService.getJwtRefreshTokenTTL()));

        return tokensResponse;
    }

    public User me() {
        UserClaims userClaims = getUserClaims();

        return userRepository.findOneById(userClaims.getId())
                .orElseThrow(() -> new UserNotFoundException(userClaims.getEmail()));
    }

    private TokensResponse generateTokens(UserClaims user) {
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return new TokensResponse(accessToken, refreshToken);
    }

    private UserClaims getUserClaims() {
        return (UserClaims) SecurityContextHolder.getContext().getAuthentication();
    }

}
