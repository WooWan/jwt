package com.jwt.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String headerAuth = req.getHeader("Authorization");
        if (req.getMethod().equals("POST")) {
            System.out.println("post 요청 됨");
            System.out.println("headerAuth = " + headerAuth);
            if (headerAuth.equals("cos")) {
                System.out.println("코스코스");
                chain.doFilter(req, res);
            }else{
                PrintWriter out = res.getWriter();
                out.println("인증 안됌");
            }
        }
        System.out.println("필터1");
    }
}
