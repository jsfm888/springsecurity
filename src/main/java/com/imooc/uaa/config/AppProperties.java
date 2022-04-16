package com.imooc.uaa.config;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "mooc")
public class AppProperties {


    @Getter
    @Setter
    private Jwt jwt = new Jwt();


    @Getter
    @Setter
    public static class Jwt {

        private String header = "Authority"; //HTTP 报头中认证字段的key

        private String prefix = "Bearer "; //HTTP 报头中认证字段的值的前缀


        //Access Token 过期时间
         private Long accessTokenExpireTime = 60_000L;

         //Refresh Token 过期时间
        private Long refreshTokenExpireTime = 30 * 24 * 3600 * 1000L;
    }

}
