package com.imooc.uaa.service;

import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;


@ConditionalOnProperty(prefix = "mooc.email-provider", name = "name", havingValue = "smtp")
@Service
@RequiredArgsConstructor
public class EmailServiceSmtpImpl implements EmailService{

    private final JavaMailSender javaMailSender;

    @Override
    public void send(String email, String msg) {
        val message = new SimpleMailMessage();
        message.setFrom("qinwenqiang_8@163.com");
        message.setTo(email);
        message.setSubject("景色分明springsecurity登录验证码");
        message.setText("验证码为: " + msg);
        javaMailSender.send(message);
    }
}
