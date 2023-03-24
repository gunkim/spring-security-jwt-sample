package io.github.gunkim.application.spring.security.provider;

import io.github.gunkim.application.spring.security.JwtAuthenticationToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import java.util.List;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final Jws<Claims> jwsClaims = (Jws<Claims>) authentication.getCredentials();
        final String subject = jwsClaims.getBody().getSubject();
        final List<String> roles = jwsClaims.getBody().get("roles", List.class);

        final var authorities = roles.stream().map(SimpleGrantedAuthority::new).toList();

        return new JwtAuthenticationToken(subject, authorities);
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
