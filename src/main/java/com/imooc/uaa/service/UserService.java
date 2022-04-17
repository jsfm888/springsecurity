package com.imooc.uaa.service;

import com.imooc.uaa.config.Constants;
import com.imooc.uaa.domain.Auth;
import com.imooc.uaa.domain.User;
import com.imooc.uaa.repository.RoleRepo;
import com.imooc.uaa.repository.UserRepo;
import com.imooc.uaa.util.JwtUtil;
import com.imooc.uaa.util.TotpUtil;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    private final TotpUtil totpUtil;

    private final RoleRepo roleRepo;

    public Auth login(String username, String password) {
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
                                        .withPassword(passwordEncoder.encode(user.getPassword()))
                                        .withMfaKey(totpUtil.encodeKeyToString());
                    return userRepo.save(userToSave);
                })
                .orElseThrow();
    }

    public UserDetails updatePassword(User user, String newPassword) {
        return userRepo.findOptionalByUsername(user.getUsername())
            .map(userFromDb -> userRepo.save(userFromDb.withPassword(newPassword)))
            .orElseThrow();
    }

    public Optional<String> createTotp(String mfaKey) {
        return totpUtil.createTotp(mfaKey);
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

    public Optional<User> findOptionalByUsernameAndPassword(String username, String password) {
        return userRepo.findOptionalByUsername(username)
            .filter(user -> passwordEncoder.matches(password, user.getPassword()));
    }
}
