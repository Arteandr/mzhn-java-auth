package com.mzhn.chemp.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class ForbiddenAccessException extends ResponseStatusException {
    public ForbiddenAccessException() {
       super(HttpStatus.FORBIDDEN);
    }
}
