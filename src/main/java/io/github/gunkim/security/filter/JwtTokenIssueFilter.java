package io.github.gunkim.security.filter;

import io.github.gunkim.security.exception.AuthMethodNotSupportedException;
import io.github.gunkim.security.filter.request.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;

public class JwtTokenIssueFilter extends AbstractAuthenticationProcessingFilter {
    private final JsonMapper jsonMapper;

    public JwtTokenIssueFilter(String defaultFilterProcessesUrl, JsonMapper jsonMapper,
                               AuthenticationSuccessHandler authenticationSuccessHandler,
                               AuthenticationFailureHandler authenticationFailureHandler) {
        super(defaultFilterProcessesUrl);
        this.jsonMapper = jsonMapper;
        this.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        this.setAuthenticationFailureHandler(authenticationFailureHandler);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {
        if (!isPostMethod(request)) {
            throw new AuthMethodNotSupportedException("Authentication method not supported");
        }

        var loginRequest = jsonMapper.readValue(request.getReader(), LoginRequest.class);
        var token = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(), loginRequest.password());

        return this.getAuthenticationManager().authenticate(token);
    }

    private boolean isPostMethod(HttpServletRequest request) {
        return HttpMethod.POST.name().equals(request.getMethod());
    }
}
