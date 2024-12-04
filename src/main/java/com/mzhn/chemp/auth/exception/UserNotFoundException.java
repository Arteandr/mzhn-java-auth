package com.mzhn.chemp.auth.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ResponseStatusException;

public class UserNotFoundException extends ResponseStatusException {
    public UserNotFoundException(String email) {
        super(HttpStatus.NOT_FOUND, "Пользователь  " + email + " не найден");
    }
}
