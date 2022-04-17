package com.imooc.uaa.service;


import com.imooc.uaa.config.Constants;
import com.imooc.uaa.domain.User;
import com.imooc.uaa.util.CryptoUtil;
import com.imooc.uaa.util.TotpUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.redisson.api.RMapCache;
import org.redisson.api.RedissonClient;
import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserCacheService {

    private final TotpUtil totpUtil;
    private final CryptoUtil cryptoUtil;
    private final RedissonClient redisson;


    public String cacheUser(User user) {
        String mfaId = cryptoUtil.randomAlphanumeric(12);
        RMapCache<String, User> cache = redisson.getMapCache(Constants.CACHE_MFA);
        if(!cache.containsKey(mfaId)) {
            cache.put(mfaId, user, totpUtil.getTimeStepInSeconds(), TimeUnit.SECONDS);
        }

        return mfaId;
    }

    public Optional<User> retrieveUser(String mfaId) {
        RMapCache<String, User> cache = redisson.getMapCache(Constants.CACHE_MFA);
        if(cache.containsKey(mfaId)) {
            return Optional.of(cache.get(mfaId));
        }

        return Optional.empty();
    }


    public Optional<User> verifyTotp(String mfaId, String code) {
        RMapCache<String, User> cache = redisson.getMapCache(Constants.CACHE_MFA);
        if(!cache.containsKey(mfaId) || cache.get(mfaId) == null ) {
            return Optional.empty();
        }
        User cacheUser = cache.get(mfaId);
        try {
            val isValid =  totpUtil.validateTotp(totpUtil.decodeKeyFromString(cacheUser.getMfaKey()), code);
            if(!isValid) {
                return Optional.empty();
            }
            //验证成功后
            cache.remove(mfaId);
            return Optional.of(cacheUser);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }

}
