package com.jwt.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        //내 서버가 응답을 할 대 json을 ks에서 처리할 수 있게 할지를 설정
        config.setAllowCredentials(true);
        //모든 ip에 응답을 허용
        config.addAllowedOrigin("*");
        // 모든 header에 허용용
       config.addAllowedHeader("*");
        // 모든 http method 에 대해서 요청 허용
        config.addAllowedMethod("*");
//        /api/** 로 들어오는 모든 설정은 config를 따른다
        source.registerCorsConfiguration("/api/**", config);

        return new CorsFilter(source);
    }
}
