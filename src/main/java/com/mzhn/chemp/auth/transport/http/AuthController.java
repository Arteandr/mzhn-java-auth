package com.mzhn.chemp.auth.transport.http;


import com.mzhn.chemp.auth.domain.User;
import com.mzhn.chemp.auth.dto.auth.AuthenticationResponse;
import com.mzhn.chemp.auth.dto.auth.TokensResponse;
import com.mzhn.chemp.auth.dto.auth.SignInRequest;
import com.mzhn.chemp.auth.dto.auth.SignUpRequest;
import com.mzhn.chemp.auth.service.AuthService;
import com.mzhn.chemp.auth.utils.jwt.JwtService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@AllArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {
    private static final String REFRESH_TOKEN_COOKIE = "refresh_token";

    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        TokensResponse tokens = authService.signUp(signUpRequest);

        return getTokenResponse(tokens);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> loginUser(@Valid @RequestBody SignInRequest signInRequest) {
        TokensResponse tokens = authService.signIn(signInRequest);

        return getTokenResponse(tokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshTokens(@CookieValue(REFRESH_TOKEN_COOKIE) String refreshToken) {
        TokensResponse tokens = authService.refreshTokens(refreshToken);

        return getTokenResponse(tokens);
    }

    @GetMapping("/me")
    public ResponseEntity<User> me() {
        User user = authService.me();

        return ResponseEntity.ok(user);
    }


    private ResponseEntity<?> getTokenResponse(TokensResponse tokens) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE, tokens.getRefreshToken())
                .httpOnly(true) // Устанавливаем HttpOnly
                .secure(true) // Устанавливаем Secure
                .path("/") // Устанавливаем путь
                .maxAge(jwtService.jwtRefreshTokenTTL * 60L) // Куки живёт 7 дней
                .sameSite("Strict") // Устанавливаем SameSite
                .build();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok().headers(headers).body(new AuthenticationResponse(tokens.getAccessToken()));
    }
}
