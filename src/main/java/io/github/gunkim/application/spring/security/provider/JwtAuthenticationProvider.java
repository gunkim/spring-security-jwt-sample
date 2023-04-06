package io.github.gunkim.application.spring.security.provider;

import io.github.gunkim.application.spring.security.JwtAuthenticationToken;
import io.github.gunkim.application.spring.security.service.TokenService;
import io.github.gunkim.application.spring.security.service.dto.TokenParserResponse;
import io.github.gunkim.domain.Role;
import java.util.List;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final TokenService tokenService;

    public JwtAuthenticationProvider(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        return authenticate((JwtAuthenticationToken) authentication);
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }

    private Authentication authenticate(final JwtAuthenticationToken authentication) throws AuthenticationException {
        final String jwtToken = authentication.getCredentials();
        final TokenParserResponse response = tokenService.parserToken(jwtToken);

        return new JwtAuthenticationToken(response.username(), authorities(response));
    }

    private List<SimpleGrantedAuthority> authorities(TokenParserResponse response) {
        return response.roles().stream()
            .map(Role::name)
            .map(SimpleGrantedAuthority::new)
            .toList();
    }
}
