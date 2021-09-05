package com.jwt.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//stateless로 설정해서 session방식 적용 해제
                .and()
                .addFilter(corsFilter) //@CrossOrigin(인증 x),  시큐리티 필터에 등록 인증
                .formLogin().disable()
                .httpBasic().disable() //basic 방식은 header에 id와 pw를 같이 요청하는 방식 (보안성 취약)
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('Role_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('Role_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access(" hasRole('Role_ADMIN')")
                .anyRequest().permitAll();
    }
}
