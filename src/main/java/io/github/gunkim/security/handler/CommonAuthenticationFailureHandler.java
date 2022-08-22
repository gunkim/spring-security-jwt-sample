package io.github.gunkim.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.gunkim.security.exception.AuthMethodNotSupportedException;
import io.github.gunkim.security.exception.JwtExpiredTokenException;
import lombok.RequiredArgsConstructor;
import org.h2.api.ErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 공통 실패 처리 핸들러
 */
@Component
@RequiredArgsConstructor
public class CommonAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private final ObjectMapper objectMapper;

    /**
     * 실패 시 처리 로직
     * TODO: 예외에 따른 메시지를 response 해줌.
     * @param request
     * @param response
     * @param exception
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        String msg = "인증 실패";
        if (exception instanceof BadCredentialsException) {
            msg = "비밀번호 불일치";
        } else if (exception instanceof AuthMethodNotSupportedException) {
            msg = "해당 요청으로 인한 로그인 미지원";
        } else if(exception instanceof JwtExpiredTokenException){
            msg = "JWT 토큰 유효기간 만료";
        }
        objectMapper.writeValue(response.getWriter(), msg);
    }
}
