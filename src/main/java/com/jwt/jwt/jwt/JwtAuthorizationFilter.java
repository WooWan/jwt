package com.jwt.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jwt.jwt.auth.PrincipalDetails;
import com.jwt.jwt.domain.User;
import com.jwt.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// security filter 가지고 있는데 그 필터중에 basicAuthenticationFilter 라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을 대 위의 필터를 무조건 거친다.
//권한이 인증 필요한 주소가 아니라면 이 필터
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {

        super(authenticationManager);
        this.userRepository = userRepository;
        System.out.println("인증이나 권한이 필요한 주소 요청이 된다.");
    }

    //인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 거치게 된다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청이 됨");
        String jwtHeader = request.getHeader("Authorization");
        System.out.println(jwtHeader );
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String username = JWT.require(Algorithm.HMAC256("cos")).build().verify(jwtToken).getClaim("username").asString();
        //서명이 정상적으로 된 경우
        if(username!=null){
            User userEntity = userRepository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            //로그인 요청을 하지 않고 jwt 토큰이 있을경우 Authentication 객체를 만들어준다.
            //session에 authorization 객체가 있는듯???
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }
    }
}
