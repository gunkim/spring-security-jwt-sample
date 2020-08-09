package com.gun.app.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * JWT 유효성 검증을 위한 Token
 */
@Getter
public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 5816307710547739210L;

    private final Jws<Claims> claimsJws;
    private final String username;

    public JwtAuthenticationToken(Jws<Claims> claimsJws){
        super(null);
        this.claimsJws = claimsJws;
        this.setAuthenticated(false);
        this.username = null;
    }

    public JwtAuthenticationToken(String username, Collection<? extends GrantedAuthority> authorities) {
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
        return null;
    }
}
