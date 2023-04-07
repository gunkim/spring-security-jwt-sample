package io.github.gunkim.application.spring.security.service;

import io.github.gunkim.application.spring.security.exception.JwtExpiredTokenException;
import io.github.gunkim.application.spring.security.service.dto.TokenParserResponse;
import io.github.gunkim.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

@Service
public class TokenService {
    private final String secretKey;
    private final long expirationTime;
    private final String issuer;

    public TokenService(
        @Value("${jwt.token.secret-key}") String secretKey,
        @Value("${jwt.token.expTime}") long expirationTime,
        @Value("${jwt.token.issuer}") String issuer) {
        this.secretKey = secretKey;
        this.expirationTime = expirationTime;
        this.issuer = issuer;
    }

    public String createToken(String username, List<GrantedAuthority> authorities) {
        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime expiredAt = issuedAt.plusMinutes(expirationTime);

        return Jwts.builder()
            .addClaims(createClaims(username, authorities))
            .setIssuer(issuer)
            .setIssuedAt(toDate(issuedAt))
            .setExpiration(toDate(expiredAt))
            .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()), SignatureAlgorithm.HS256).compact();
    }

    public TokenParserResponse parserToken(String token) throws BadCredentialsException, JwtExpiredTokenException {
        try {
            return tokenParserResponse(
                Jwts.parserBuilder()
                    .setSigningKey(secretKey.getBytes())
                    .build()
                    .parseClaimsJws(token)
            );
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("Invalid JWT token: ", ex);
        } catch (ExpiredJwtException expiredEx) {
            throw new JwtExpiredTokenException("JWT Token expired", expiredEx);
        }
    }

    @SuppressWarnings("unchecked")
    private TokenParserResponse tokenParserResponse(Jws<Claims> claimsJws) {
        String username = claimsJws.getBody().getSubject();
        List<Role> roles = claimsJws.getBody().get("roles", List.class);

        return new TokenParserResponse(username, roles);
    }

    private Claims createClaims(String username, List<GrantedAuthority> authorities) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", authorities.stream().map(Object::toString).toList());
        return claims;
    }

    private Date toDate(LocalDateTime dateTime) {
        return Date.from(dateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
}
