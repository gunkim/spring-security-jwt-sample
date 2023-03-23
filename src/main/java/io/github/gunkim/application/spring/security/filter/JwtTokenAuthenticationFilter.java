package io.github.gunkim.application.spring.security.filter;

import io.github.gunkim.application.spring.security.JwtAuthenticationToken;
import io.github.gunkim.application.spring.security.config.SecurityConfig;
import io.github.gunkim.application.spring.security.service.TokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class JwtTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private final AuthenticationFailureHandler failureHandler;
    private final TokenService tokenService;

    public JwtTokenAuthenticationFilter(final RequestMatcher matcher, final AuthenticationFailureHandler failureHandler,
        final TokenService tokenService) {
        super(matcher);
        this.failureHandler = failureHandler;
        this.tokenService = tokenService;
    }

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
        throws AuthenticationException {
        final String tokenPayload = request.getHeader(SecurityConfig.AUTHENTICATION_HEADER_NAME);
        final Jws<Claims> claimsJws = tokenService.parserToken(tokenPayload);

        return getAuthenticationManager().authenticate(new JwtAuthenticationToken(claimsJws));
    }

    @Override
    protected void successfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
        final FilterChain chain, final Authentication authentication) throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
        final AuthenticationException authenticationException) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, authenticationException);
    }
}
