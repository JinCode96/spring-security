package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * OAuth2
 * 1. 코드 받기 (인증) -> 라이브러리가 자동으로 받아옴
 * 2. 엑세스 토큰 (권한) -> 라이브러리가 자동으로 받아옴
 * 3. 사용자 프로필 정보 가져오기
 * 4 - 1. 그 정보를 토대로 회원가입 자동 진행
 * 4 - 2. 혹은 추가 정보가 필요하다면, 추가적인 회원가입 절차를 더할 수 있다.
 */
@Configuration
@EnableWebSecurity // 시큐리티 활성화
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, (preAuthorize, postAuthorize) 어노테이션 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalOauth2UserService principalOauth2UserService; // 로그인 후처리 담당 클래스

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(c -> c.disable())

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll() // resource 에 대해서는 모든 요청 허용

                        .requestMatchers("/user/**").authenticated() // 이 주소는 인증이 필요
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER") // 권한이 있어야 통과
                        .requestMatchers("/admin/**").hasRole("ADMIN") // 권한이 있어야 통과
                        .anyRequest().permitAll() // 다른 요청은 모두 통과
                )

                .formLogin(form -> form
                        .loginPage("/loginForm").permitAll() // 기본 로그인 화면 설정
                        .loginProcessingUrl("/login") // login 주소 호출 시 시큐리티가 낚아채서 대신 로그인 진행
                        .defaultSuccessUrl("/") // 시큐리티는 로그인 후 자동으로 가려던 웹 페이지로 이동시켜준다.
                )

                .oauth2Login(cus -> cus
                        .loginPage("/loginForm") // OAuth2 로그인 페이지 설정
                        .userInfoEndpoint(c -> c.userService(principalOauth2UserService)) // 구글 로그인완료 후처리 필요. tip. 코드 X (엑세스 토큰 + 사용자 프로필 정보 O)
                );

        return http.build();
    }
}
