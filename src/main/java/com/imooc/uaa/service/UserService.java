package com.imooc.uaa.service;

import com.imooc.uaa.config.Constants;
import com.imooc.uaa.domain.Auth;
import com.imooc.uaa.domain.User;
import com.imooc.uaa.repository.RoleRepo;
import com.imooc.uaa.repository.UserRepo;
import com.imooc.uaa.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.naming.AuthenticationException;
import java.util.Set;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    private final RoleRepo roleRepo;

    public Auth login(String username, String password) throws AuthenticationException {
        return userRepo.findOptionalByUsername(username)
            .filter(user -> passwordEncoder.matches(password, user.getPassword()))
            .map(user -> new Auth(
                jwtUtil.createAccessToken(user),
                jwtUtil.createRefreshToken(user)
            ))
            .orElseThrow(() -> new BadCredentialsException("用户名或密码错误"));
    }

    @Transactional
    public User register(User user) {
        return roleRepo.findOptionalByAuthority(Constants.ROLE_USER)
                .map(role -> {
                    val userToSave = user
                                        .withAuthorities(Set.of(role))
                                        .withPassword(passwordEncoder.encode(user.getPassword()));

                    return userRepo.save(userToSave);
                })
                .orElseThrow();
    }



    public boolean isUsernameExisted(String username) {
        return userRepo.countByUsername(username) > 0;
    }

    public boolean isEmailExisted(String email) {
        return userRepo.countByEmail(email) > 0;
    }

    public boolean isMobileExisted(String mobile) {
        return userRepo.countByMobile(mobile) > 0;
    }
}
