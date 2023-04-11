package io.github.gunkim.application.spring.security.service;

import io.github.gunkim.application.spring.security.exception.JwtExpiredTokenException;
import io.github.gunkim.application.spring.security.service.dto.TokenParserResponse;
import io.github.gunkim.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

@Service
public class TokenService {
    private final SecretKey key;
    private final long expirationTime;
    private final String issuer;

    public TokenService(
        @Value("${jwt.token.secret-key}") String key,
        @Value("${jwt.token.expTime}") long expirationTime,
        @Value("${jwt.token.issuer}") String issuer) {
        this.key = Keys.hmacShaKeyFor(key.getBytes());
        this.expirationTime = expirationTime;
        this.issuer = issuer;
    }

    public String createToken(String username, Collection<GrantedAuthority> authorities) {
        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime expiredAt = issuedAt.plusMinutes(expirationTime);

        return Jwts.builder()
            .addClaims(createClaims(username, authorities))
            .setIssuer(issuer)
            .setIssuedAt(toDate(issuedAt))
            .setExpiration(toDate(expiredAt))
            .signWith(key)
            .compact();
    }

    public TokenParserResponse parserToken(String token) throws BadCredentialsException, JwtExpiredTokenException {
        try {
            return tokenParserResponse(
                Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
            );
        } catch (SignatureException | UnsupportedJwtException | MalformedJwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("Invalid JWT token", ex);
        } catch (ExpiredJwtException expiredEx) {
            throw new JwtExpiredTokenException("JWT Token expired", expiredEx);
        }
    }

    @SuppressWarnings("unchecked")
    private TokenParserResponse tokenParserResponse(Jws<Claims> claimsJws) {
        String username = claimsJws.getBody().getSubject();
        List<String> roles = claimsJws.getBody().get("roles", List.class);

        return new TokenParserResponse(username, roles.stream().map(Role::of).toList());
    }

    private Claims createClaims(String username, Collection<GrantedAuthority> authorities) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", authorities.stream().map(Object::toString).toList());
        return claims;
    }

    private Date toDate(LocalDateTime dateTime) {
        return Date.from(dateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
}
