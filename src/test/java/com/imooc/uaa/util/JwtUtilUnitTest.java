package com.imooc.uaa.util;

import com.imooc.uaa.config.AppProperties;
import com.imooc.uaa.domain.Role;
import com.imooc.uaa.domain.User;
import io.jsonwebtoken.Jwts;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
public class JwtUtilUnitTest {

    private JwtUtil jwtUtil;

    @BeforeEach
    public void setup() {
        jwtUtil = new JwtUtil(new AppProperties());
    }

    @Test
    public void givenUserDetails_thenCreateTokenSuccess() {
        val username = "user";
        val authorities = Set.of(
                            Role.builder()
                            .authority("ROLE_USER")
                            .build(),
                            Role.builder()
                            .authority("ROLE_ADMIN")
                            .build());
        val user = User.builder().username(username).authorities(authorities).build();
        //创建jwt
        val token = jwtUtil.createAccessToken(user);
        //解析token
        val parsedClaims = Jwts.parserBuilder()
            .setSigningKey(jwtUtil.accessKey)
            .build()
            .parseClaimsJws(token)
            .getBody();

        assertEquals(username, parsedClaims.getSubject(), "解析后的 Subject 应该是用户名");
    }
}
