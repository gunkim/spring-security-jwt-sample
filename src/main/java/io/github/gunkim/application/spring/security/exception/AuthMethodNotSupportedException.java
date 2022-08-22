package io.github.gunkim.application.spring.security.exception;

import org.springframework.security.authentication.AuthenticationServiceException;

/**
 * 인증(Authentication) 미지원 예외 클래스
 */
public class AuthMethodNotSupportedException extends AuthenticationServiceException {
    private static final long serialVersionUID = 4986219033524607543L;

    public AuthMethodNotSupportedException(String msg) {
        super(msg);
    }
}
