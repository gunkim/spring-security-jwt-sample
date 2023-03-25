package io.github.gunkim.application.spring.security;

import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private final String jwtToken;
    private final String username;

    public JwtAuthenticationToken(final String jwtToken) {
        super(null);
        this.setAuthenticated(false);
        this.jwtToken = jwtToken;
        this.username = null;
    }

    public JwtAuthenticationToken(final String username, final Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.eraseCredentials();
        super.setAuthenticated(true);
        this.username = username;
        this.jwtToken = null;
    }

    @Override
    public String getCredentials() {
        return this.jwtToken;
    }

    @Override
    public String getPrincipal() {
        return username;
    }
}
