package com.mzhn.chemp.auth.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Ответ с access токеном")
public class AuthenticationResponse {
    @Schema(description = "Access токен")
    private String accessToken;
}
