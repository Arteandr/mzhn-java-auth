package com.mzhn.chemp.auth.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(description = "Запрос на регистрацию")
public class SignUpRequest {
    @Schema(description = "Email пользователя")
    @Email(message = "Неверный email")
    @NotBlank(message = "Email пользователя не может быть пустым")
    private String email;

    @Schema(description = "Пароль пользователя")
    @Size(min = 8, max = 255, message = "Длина пароля должна быть от 8 до 255 символов")
    @NotBlank(message = "Пароль не может быть пустым")
    private String password;

    @Schema(description = "Имя пользователя")
    private String firstName;

    @Schema(description = "Фамилия пользователя")
    private String lastName;
}