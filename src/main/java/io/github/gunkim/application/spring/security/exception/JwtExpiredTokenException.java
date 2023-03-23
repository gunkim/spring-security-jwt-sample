package io.github.gunkim.application.spring.security.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtExpiredTokenException extends AuthenticationException {
    private final String token;

    public JwtExpiredTokenException(final String token, final String msg, final Throwable t) {
        super(msg, t);
        this.token = token;
    }
}
