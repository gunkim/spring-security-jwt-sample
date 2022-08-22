package io.github.gunkim.application.spring.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.gunkim.application.spring.security.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;

/**
 * 비동기 로그인 성공 처리 핸들러
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AsyncLoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final ObjectMapper objectMapper;
    private final JwtUtil jwtUtil;

    /**
     * 성공 시 처리 로직.
     * TODO: 토큰을 발행하여 response해준다.
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String username = (String) authentication.getPrincipal();
        List<GrantedAuthority> authorities = (List<GrantedAuthority>) authentication.getAuthorities();
        String jwtToken = jwtUtil.createToken(username, authorities);

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), jwtToken);

        HttpSession session = request.getSession(false);

        if (session != null) {
            session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        }
    }
}
