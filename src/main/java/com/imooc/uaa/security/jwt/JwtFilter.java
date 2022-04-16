package com.imooc.uaa.security.jwt;

import com.imooc.uaa.config.AppProperties;
import com.imooc.uaa.util.CollectionUtil;
import com.imooc.uaa.util.JwtUtil;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import java.util.Optional;

import static java.util.stream.Collectors.toList;

@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final AppProperties appProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(checkJwtToken(request)) {
            //有值
            validateToken(request)
                .filter(claims -> claims.get("authorities") != null)
                .ifPresentOrElse(this::setupSpringAuthentication,  //有值
                                SecurityContextHolder::clearContext);  //空值
        }

        filterChain.doFilter(request, response);
    }

    private void setupSpringAuthentication(Claims claims) {
        val rawList = CollectionUtil.convertObjectToList(claims.get("authorities"));
        val authorities = rawList.stream()
                                            .map(String::valueOf)
                                            .map(SimpleGrantedAuthority::new)
                                            .collect(toList());
        val authentication = new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }


    /**
     * 解析验证 token
     * @param request
     * @return
     */
    private Optional<Claims> validateToken(HttpServletRequest request) {
        String jwtToken = request.getHeader(appProperties.getJwt().getHeader()).replace(appProperties.getJwt().getPrefix(), "");
        try {
            return Optional.of(Jwts.parserBuilder()
                                .setSigningKey(JwtUtil.accessKey)
                                .build().parseClaimsJws(jwtToken).getBody());
        }catch (ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /**
     * 检查Jwt Token 是否存在在报头中
     * @param request
     * @return
     */
    private boolean checkJwtToken(HttpServletRequest request) {
        String authenticationHeader = request.getHeader(appProperties.getJwt().getHeader());
        return authenticationHeader != null && authenticationHeader.startsWith(appProperties.getJwt().getPrefix());
    }
}
