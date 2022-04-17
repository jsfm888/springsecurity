package com.imooc.uaa.rest;

import com.imooc.uaa.domain.Auth;
import com.imooc.uaa.domain.MfaType;
import com.imooc.uaa.domain.User;
import com.imooc.uaa.domain.dto.LoginDto;
import com.imooc.uaa.domain.dto.SendTotpDto;
import com.imooc.uaa.domain.dto.UserDto;
import com.imooc.uaa.domain.dto.VerifyTotpDto;
import com.imooc.uaa.exception.*;
import com.imooc.uaa.service.EmailService;
import com.imooc.uaa.service.UserCacheService;
import com.imooc.uaa.service.UserService;
import com.imooc.uaa.util.JwtUtil;
import com.imooc.uaa.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@RestController
@RequestMapping("/authorize")
public class AuthorizeResource {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    private final EmailService emailService;

    private final UserCacheService userCacheService;

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

        // 2. 把 userDto 转换成 User , 给一个默认角色(ROLE_USER), 然后保存。
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
    public ResponseEntity<?> login(@Valid @RequestBody LoginDto loginDto) throws Exception {
        return userService.findOptionalByUsernameAndPassword(loginDto.getUsername(), loginDto.getPassword())
                .map(user -> {
                    //1. 升级密码编码
                    userService.updatePassword(user, loginDto.getPassword());
                    //2. 验证
                    if(!user.isEnabled()) {
                        throw new UserNotEnabledProblem();
                    }
                    if(!user.isAccountNonLocked()) {
                        throw new UserAccountLockedProblem();
                    }
                    if(!user.isAccountNonExpired()) {
                        throw new UserAccountExpiredProblem();
                    }

                    //3. 判断 usingMfa 为false, 直接返回token
                    if(!user.isUsingMfa()) {
                        return ResponseEntity.ok().body(userService.login(loginDto.getUsername(), loginDto.getPassword()));
                    }
                    //4. 使用多因子认证
                    val mfaId = userCacheService.cacheUser(user);
                    //5. "X-Authenticate": "mfa", "realm=" + mfaId
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .header("X-Authenticate", "mfa", "realm=" + mfaId)
                        .build();
                })
            .orElseThrow(() -> new BadCredentialsException("用户名或密码错误"));

        //return userService.login(loginDto.getUsername(), loginDto.getPassword());
    }


    @PutMapping("/totp")  //totp就是发送的短信或邮箱 code
    public void sendTotp(@RequestBody @Valid SendTotpDto sendTotpDto) {

        //精辟
        userCacheService.retrieveUser(sendTotpDto.getMfaId())
            //map只能把一个对象转换成另一个对象来作为流中的元素，而flatMap可以转换为多个对象作为流中的元素
            //例如：Optional<Optional<String>>   Pair.of 用于将两个对象传下去
            .flatMap(user -> userService.createTotp(user.getMfaKey()).map(code -> Pair.of(user, code)))
            .ifPresentOrElse(pair -> {  //存在
                if(sendTotpDto.getMfaType() == MfaType.SMS) { //短信方式

                } else {  //邮箱方式
                    emailService.send(pair.getFirst().getEmail(), pair.getSecond());
                }
            }, () -> {
                throw new InvalidTotpProblem();  //为空
            });
    }

    @PostMapping("/totp")
    public Auth verifyTotp(@RequestBody @Valid VerifyTotpDto verifyTotpDto) {
        return userCacheService.verifyTotp(verifyTotpDto.getMfaId(), verifyTotpDto.getCode())
                    .map(user -> userService.login(user.getUsername(), user.getPassword()))
                    .orElseThrow(() -> new InvalidTotpProblem());
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
