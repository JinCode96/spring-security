package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @ResponseBody
    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @ResponseBody
    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @ResponseBody
    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    //    @ResponseBody
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        log.info("user={}", user);
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        user.setRole("USER");

        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN") // 이 권한을 가진 사람만 접근 가능
    @ResponseBody
    @GetMapping("/info")
    public String info() {
        return "개인정보";
    }

    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MANAGER')") // 여러 권한을 줄 때 사용, 잘 사용은 안 함
    @ResponseBody
    @GetMapping("/data")
    public String data() {
        return "데이터 정보";
    }

    /**
     * 회원 정보 세션에서 가져오기
     * 일반 회원, OAuth 회원 전부 받을 수 있게 되었다. (UserDetails, OAuth2User 타입 모두 받음)
     */
    @ResponseBody
    @GetMapping("/test/login")
    public String testLogin(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails.getUser={}", principalDetails.getUser());
        log.info("principalDetails.getAttributes={}", principalDetails.getAttributes());
        return "세션 정보 확인";
    }

}
