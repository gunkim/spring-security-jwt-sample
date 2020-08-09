package com.gun.app.security.exception;

import org.springframework.security.authentication.AuthenticationServiceException;

public class AuthMethodNotSupportedException extends AuthenticationServiceException {
    private static final long serialVersionUID = 4986219033524607543L;

    public AuthMethodNotSupportedException(String msg) {
        super(msg);
    }
}
