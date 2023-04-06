package io.github.gunkim.application.spring.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.gunkim.application.spring.security.exception.AuthMethodNotSupportedException;
import io.github.gunkim.application.spring.security.model.LoginRequest;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class JwtTokenIssueFilter extends AbstractAuthenticationProcessingFilter {
    private final ObjectMapper objectMapper;

    public JwtTokenIssueFilter(final String defaultFilterProcessesUrl, final ObjectMapper objectMapper,
        final AuthenticationSuccessHandler authenticationSuccessHandler,
        final AuthenticationFailureHandler authenticationFailureHandler) {
        super(defaultFilterProcessesUrl);
        this.objectMapper = objectMapper;
        this.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        this.setAuthenticationFailureHandler(authenticationFailureHandler);
    }

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
        throws AuthenticationException, IOException {
        if (!HttpMethod.POST.name().equals(request.getMethod())) {
            throw new AuthMethodNotSupportedException("Authentication method not supported");
        }

        final var loginRequest = objectMapper.readValue(request.getReader(), LoginRequest.class);
        final var token = new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password());

        return this.getAuthenticationManager().authenticate(token);
    }
}
