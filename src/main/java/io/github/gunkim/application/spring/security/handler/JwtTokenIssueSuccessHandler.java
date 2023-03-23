package io.github.gunkim.application.spring.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.gunkim.application.spring.security.service.TokenService;
import java.io.IOException;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenIssueSuccessHandler implements AuthenticationSuccessHandler {
    private final ObjectMapper objectMapper;
    private final TokenService tokenService;

    public JwtTokenIssueSuccessHandler(final ObjectMapper objectMapper, final TokenService tokenService) {
        this.objectMapper = objectMapper;
        this.tokenService = tokenService;
    }

    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
        Authentication authentication) throws IOException {
        final String username = ((User) authentication.getPrincipal()).getUsername();
        final var authorities = (List<GrantedAuthority>) authentication.getAuthorities();
        final String jwtToken = tokenService.createToken(username, authorities);

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), jwtToken);

        final var session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        }
    }
}
