package com.mzhn.chemp.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ResponseStatusException;

public class UserAlreadyExistsException extends ResponseStatusException {
    public UserAlreadyExistsException(String email) {
        super(HttpStatus.CONFLICT, "Пользователь с email " + email + " уже существует");
    }
}
