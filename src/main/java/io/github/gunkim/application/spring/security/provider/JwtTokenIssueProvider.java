package io.github.gunkim.application.spring.security.provider;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtTokenIssueProvider implements AuthenticationProvider {
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var username = (String) authentication.getPrincipal();
        var password = (String) authentication.getCredentials();

        return authenticate(username, password);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

    private UsernamePasswordAuthenticationToken authenticate(String username, String password) {
        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("인증 실패. username or password 불일치");
        }

        return new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities(user));
    }

    private static List<SimpleGrantedAuthority> authorities(UserDetails user) {
        return user.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .map(SimpleGrantedAuthority::new)
            .toList();
    }
}
