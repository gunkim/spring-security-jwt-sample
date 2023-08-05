package io.github.gunkim.application.spring.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.gunkim.application.spring.security.handler.response.TokenResponse;
import io.github.gunkim.application.spring.security.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.util.Objects.isNull;

@Component
@RequiredArgsConstructor
public class JwtTokenIssueSuccessHandler implements AuthenticationSuccessHandler {
    private final ObjectMapper objectMapper;
    private final TokenService tokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        onAuthenticationSuccess(request, response, (UsernamePasswordAuthenticationToken) authentication);
    }

    private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         UsernamePasswordAuthenticationToken authentication) throws IOException {
        String username = authentication.getPrincipal().toString();
        var authorities = authentication.getAuthorities();

        var tokenResponse = new TokenResponse(tokenService.createToken(username, authorities));

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), tokenResponse);

        var session = request.getSession(false);
        if (!isNull(session)) {
            session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        }
    }
}
