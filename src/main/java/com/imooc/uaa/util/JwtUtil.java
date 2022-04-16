package com.imooc.uaa.util;

import com.imooc.uaa.config.AppProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final AppProperties appProperties;

    //用于签名访问令牌的秘钥
    public static final Key accessKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    //用于签名刷新令牌的秘钥
    public static final Key refreshKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);


    public String createAccessToken(UserDetails userDetails) {
        return createJwtToken(userDetails, appProperties.getJwt().getAccessTokenExpireTime(), accessKey);
    }

    public String createRefreshToken(UserDetails userDetails) {
        return createJwtToken(userDetails, appProperties.getJwt().getRefreshTokenExpireTime() ,refreshKey);
    }


    public String createJwtToken(UserDetails userDetails, Long timeToExpire, Key key) {
        return Jwts.builder()
            .setId("imooc")
            .claim("authorities", userDetails.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList()))
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + timeToExpire))
            .signWith(key, SignatureAlgorithm.HS512)
            .compact();
    }

    public boolean validateAccessToken(String jwtToken) {
        return validateToken(jwtToken, accessKey, true);
    }

    public boolean validateRefreshToken(String jwtToken) {
        return validateToken(jwtToken, refreshKey, true);
    }

    public boolean validateAccessTokenWithoutExpiration(String jwtToken) {
        return validateToken(jwtToken, accessKey, false);
    }


    public boolean validateToken(String token, Key signKey, boolean isExpiredInvalid) {
        try {
            Jwts.parserBuilder().setSigningKey(signKey).build().parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            if(e instanceof ExpiredJwtException) {
                return !isExpiredInvalid;
            }
            return false;
        }
    }


    public String createAccessTokenWithRefreshToken(String token) {
        return parseClaims(token, refreshKey)
            .map(claims -> Jwts.builder()
                        .setClaims(claims)
                        .setExpiration(new Date(System.currentTimeMillis() + appProperties.getJwt().getAccessTokenExpireTime()))
                        .setIssuedAt(new Date())
                        .signWith(accessKey, SignatureAlgorithm.HS512)
                        .compact()
            )
            .orElseThrow(() -> new AccessDeniedException("访问被拒绝"));
    }

    private Optional<Claims> parseClaims(String token, Key key) {
        try {
            val claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
            return Optional.of(claims);
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
