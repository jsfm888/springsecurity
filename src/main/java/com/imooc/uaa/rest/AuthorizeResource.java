package com.imooc.uaa.rest;

import com.imooc.uaa.domain.Auth;
import com.imooc.uaa.domain.User;
import com.imooc.uaa.domain.dto.LoginDto;
import com.imooc.uaa.domain.dto.UserDto;
import com.imooc.uaa.exception.DuplicateProblem;
import com.imooc.uaa.repository.UserRepo;
import com.imooc.uaa.service.UserService;
import com.imooc.uaa.util.JwtUtil;
import com.imooc.uaa.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;
import javax.validation.Valid;

@RequiredArgsConstructor
@RestController
@RequestMapping("/authorize")
public class AuthorizeResource {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final UserRepo userRepo;

    @GetMapping(value="greeting")
    public String sayHello() {
        return "hello world";
    }

    @PostMapping("/register")
    public void register(@Valid @RequestBody UserDto userDto) {
        //1. 检查 username, email, mobile 都是唯一的， 所以要查询数据库确保唯一
        if(userService.isUsernameExisted(userDto.getUsername())) {
            throw new DuplicateProblem("用户名重复");
        }
        if(userService.isEmailExisted(userDto.getEmail())) {
            throw new DuplicateProblem("电邮重复");
        }

        if(userService.isMobileExisted(userDto.getMobile())) {
            throw new DuplicateProblem("手机号重复");
        }


        //TODO: 2. 把 userDto 转换成 User , 给一个默认角色(ROLE_USER), 然后保存。
        val user = User.builder()
                    .username(userDto.getUsername())
                    .email(userDto.getEmail())
                    .name(userDto.getName())
                    .mobile(userDto.getMobile())
                    .password(userDto.getPassword())
                    .build();


        userService.register(user);
    }







    @GetMapping("/problem")
    public void raiseProblem() {
        throw new AccessDeniedException("You do not have the privilege");
    }

    @GetMapping("/anonymous")
    public String getAnonymous() {
        return SecurityUtil.getCurrentLogin();
    }


    @PostMapping("/token")
    public Auth login(@Valid @RequestBody LoginDto loginDto) throws Exception {
        return userService.login(loginDto.getUsername(), loginDto.getPassword());
    }

    @PostMapping("/token/refresh")
    public Auth refreshToken(@RequestHeader("Authorization") String authorization,
                             @RequestParam String refreshToken) throws AccessDeniedException {
        val PREFIX = "Bearer";
        val accessToken = authorization.replace(PREFIX, "");
        if(jwtUtil.validateRefreshToken(refreshToken) && jwtUtil.validateAccessTokenWithoutExpiration(accessToken)) {
            return new Auth(jwtUtil.createAccessTokenWithRefreshToken(refreshToken), refreshToken);
        }

        throw new AccessDeniedException("访问被拒绝");
    }
}
