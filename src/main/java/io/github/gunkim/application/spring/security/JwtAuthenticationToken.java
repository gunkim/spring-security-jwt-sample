package io.github.gunkim.application.spring.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private final Jws<Claims> claimsJws;
    private final String username;

    public JwtAuthenticationToken(final Jws<Claims> claimsJws) {
        super(null);
        this.claimsJws = claimsJws;
        this.setAuthenticated(false);
        this.username = null;
    }

    public JwtAuthenticationToken(final String username, final Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.eraseCredentials();
        this.username = username;
        super.setAuthenticated(true);
        this.claimsJws = null;
    }

    @Override
    public Object getCredentials() {
        return this.claimsJws;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }
}
