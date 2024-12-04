package com.mzhn.chemp.auth.exception;

import com.mzhn.chemp.auth.domain.ERole;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class RoleNotFoundException extends ResponseStatusException {
    public RoleNotFoundException(ERole role) {
        super(HttpStatus.NOT_FOUND, "Роль" + role + "не найдена");
    }
}
