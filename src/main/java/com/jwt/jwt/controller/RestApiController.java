package com.jwt.jwt.controller;

import com.jwt.jwt.domain.User;
import com.jwt.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping("home")
    public String home() {
        return "home";
    }

    @PostMapping("/token")
    public String token() {
        return "token";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입";
    }

    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }
    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
