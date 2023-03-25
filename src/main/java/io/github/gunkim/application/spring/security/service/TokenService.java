package io.github.gunkim.application.spring.security.service;

import io.github.gunkim.application.spring.security.exception.JwtExpiredTokenException;
import io.github.gunkim.application.spring.security.service.dto.TokenParserResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneId;
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

    public TokenService(@Value("${jwt.token.secret-key}") final String secretKey, @Value("${jwt.token.expTime}") final long expirationTime,
            @Value("${jwt.token.issuer}") final String issuer) {
        this.secretKey = secretKey;
        this.expirationTime = expirationTime;
        this.issuer = issuer;
    }

    public String createToken(String username, List<GrantedAuthority> authorities) {
        LocalDateTime currentTime = LocalDateTime.now();

        return Jwts.builder()
                .addClaims(createClaims(username, authorities))
                .setIssuer(issuer)
                .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
                .setExpiration(Date.from(currentTime.plusMinutes(expirationTime).atZone(ZoneId.systemDefault()).toInstant()))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()), SignatureAlgorithm.HS256)
                .compact();
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
            throw new JwtExpiredTokenException(expiredEx.toString(), "JWT Token expired", expiredEx);
        }
    }

    private TokenParserResponse tokenParserResponse(Jws<Claims> claimsJws) {
        return new TokenParserResponse(claimsJws.getBody().getSubject(), claimsJws.getBody().get("roles", List.class));
    }

    private Claims createClaims(final String username, final List<GrantedAuthority> authorities) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", authorities.stream().map(Object::toString).toList());
        return claims;
    }
}
