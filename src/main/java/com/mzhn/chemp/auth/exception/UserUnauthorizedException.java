package com.mzhn.chemp.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class UserUnauthorizedException extends ResponseStatusException {
    public UserUnauthorizedException() {
        super(HttpStatus.UNAUTHORIZED, "");
    }
}
