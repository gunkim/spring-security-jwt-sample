package com.gun.app.security;

import com.gun.app.security.model.UserContext;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 5816307710547739210L;

    private final Jws<Claims> claimsJws;
    private final UserContext userContext;

    public JwtAuthenticationToken(Jws<Claims> claimsJws){
        super(null);
        this.claimsJws = claimsJws;
        this.setAuthenticated(false);
        this.userContext = null;
    }

    public JwtAuthenticationToken(UserContext userContext, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.eraseCredentials();
        this.userContext = userContext;
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
