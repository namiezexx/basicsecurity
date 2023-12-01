package io.security.basicsecurity.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()  // 인가에 대한 설정
                .anyRequest().authenticated() // 모든 요청은 인가를 받은 상태에서 접근 가능
        ;

        http
                .formLogin()  // form 을 통한 인증 설정
        ;
    }
}
