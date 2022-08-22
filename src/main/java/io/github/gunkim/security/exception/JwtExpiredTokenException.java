package io.github.gunkim.security.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * 유효하지 않은 JWT 토큰 예외 클래스
 */
public class JwtExpiredTokenException extends AuthenticationException {
    private static final long serialVersionUID = -5959543783324224864L;

    private String token;

    public JwtExpiredTokenException(String msg) {
        super(msg);
    }

    public JwtExpiredTokenException(String token, String msg, Throwable t) {
        super(msg, t);
        this.token = token;
    }
}
