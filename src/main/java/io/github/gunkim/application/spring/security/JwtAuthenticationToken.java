package io.github.gunkim.application.spring.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Objects;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private final String jwtToken;
    private final String username;

    public JwtAuthenticationToken(String jwtToken) {
        super(null);
        this.setAuthenticated(false);
        this.jwtToken = jwtToken;
        this.username = null;
    }

    public JwtAuthenticationToken(String username, Collection<? extends GrantedAuthority> authorities) {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        JwtAuthenticationToken that = (JwtAuthenticationToken) o;
        return Objects.equals(jwtToken, that.jwtToken) && Objects.equals(username, that.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), jwtToken, username);
    }
}
