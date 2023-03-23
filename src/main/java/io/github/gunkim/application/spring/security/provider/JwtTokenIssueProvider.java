package io.github.gunkim.application.spring.security.provider;

import static java.util.Objects.isNull;

import io.github.gunkim.application.spring.security.service.CustomUserDetailsService;
import java.util.List;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenIssueProvider implements AuthenticationProvider {
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService customUserDetailsService;

    public JwtTokenIssueProvider(final PasswordEncoder passwordEncoder,
        final CustomUserDetailsService customUserDetailsService) {
        this.passwordEncoder = passwordEncoder;
        this.customUserDetailsService = customUserDetailsService;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        if (isNull(authentication)) {
            throw new IllegalArgumentException("authentication 발급 오류");
        }

        final var username = (String) authentication.getPrincipal();
        final var password = (String) authentication.getCredentials();

        final var user = customUserDetailsService.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("인증 실패. username or password 불일치");
        }

        List<SimpleGrantedAuthority> authorities = user.getAuthorities().stream()
            .map(authority -> new SimpleGrantedAuthority(authority.getAuthority())).toList();

        return new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities);
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
