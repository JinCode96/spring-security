package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * SecurityConfig 에서 loginProcessingUrl("/login");
 * /login 요청이 오면 자동으로 UserDetailsService 타입으로 IOC 되어있는 loadUserByUsername() 함수가 실행된다.
 */
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * <input ... name="username" ... > 에서 username 이 맞아야 동작한다.
     * 시큐리티 session(내부 Authentication(내부 PrincipalDetails)) 이 과정을 해준다.
     * 최종적으로 Security Session 에 값이 저장된다.
     * 로그인 완료
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        if (userEntity != null) {
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
