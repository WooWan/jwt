package com.jwt.jwt.auth;

import com.jwt.jwt.domain.User;
import com.jwt.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//http://localhost:8080/login 호출할 때 동작한다.
@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("loadUserByUsername");
        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }

}
