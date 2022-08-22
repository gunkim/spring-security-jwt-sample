package io.github.gunkim.application.spring.security.util;

import io.github.gunkim.application.spring.security.exception.JwtExpiredTokenException;
import io.jsonwebtoken.*;
import lombok.ToString;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT 발급 및 파싱을 위한 유틸
 */
@ToString
@Component
public class JwtUtil {
    @Value("${jwt.token.secret-key}")
    private String secretKey;
    @Value("${jwt.token.expTime}")
    private long expirationTime;
    @Value("${jwt.token.issuer}")
    private String issuer;

    /**
     * JWT 토큰 생성
     * @param username
     * @param authorities
     * @return
     */
    public String createToken(String username, List<GrantedAuthority> authorities){
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", authorities.stream().map(role -> role.toString()).collect(Collectors.toList()));

        LocalDateTime currentTime = LocalDateTime.now();

        return Jwts.builder()
                .setClaims(claims)
                .setIssuer(issuer)
                .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
                .setExpiration(Date.from(currentTime.plusMinutes(expirationTime)
                        .atZone(ZoneId.systemDefault()).toInstant()))
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }

    /**
     * JWT 토큰 파싱
     * @param token
     * @return
     * @throws BadCredentialsException
     * @throws JwtExpiredTokenException
     */
    public Jws<Claims> parserToken(String token) throws BadCredentialsException, JwtExpiredTokenException{
        Jws<Claims> claimsJws = null;
        try {
            claimsJws = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException | SignatureException ex) {
            throw new BadCredentialsException("Invalid JWT token: ", ex);
        } catch (ExpiredJwtException expiredEx) {
            throw new JwtExpiredTokenException(claimsJws.toString(), "JWT Token expired", expiredEx);
        }
        return claimsJws;
    }
}
