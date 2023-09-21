package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import lombok.Data;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * 스프링 시큐리티에서 사용자의 정보를 담는 인터페이스인 UserDetails 의 구현체
 * security session => Authentication => UserDetails(PrincipalDetails)
 */
@Data
public class PrincipalDetails implements UserDetails, OAuth2User { // @AuthenticationPrincipal 로 일반회원, oauth 회원 정보를 모두 받기 위해 이렇게 상속받기

    private User user;
    private Map<String, Object> attributes; // oauth 유저

    // 일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // oauth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    /**
     * @return 계정의 권한 목록
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(() -> {
            return "ROLE_" + user.getRole();
        }); // ROLE_USER
        return collect;
    }

    /**
     * @return 계정의 비밀번호
     */
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    /**
     * @return 계정의 고유한 값 (PK)
     */
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    /**
     * @return 계정의 만료 여부
     */
    @Override
    public boolean isAccountNonExpired() {
        return true; // 만료 안됨
    }

    /**
     * @return 계정의 잠김 여부
     */
    @Override
    public boolean isAccountNonLocked() {
        return true; // 잠기지 않음
    }

    /**
     * @return 계정의 비밀번호 만료 여부
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true; // 만료 안됨
    }

    /**
     * @return 계정의 활성화 여부
     */
    @Override
    public boolean isEnabled() {
        // 1년이 지나면 휴면 계정으로 return false 할 수 있다.
        return true; // 활성화 되어있음
    }

    // OAuth2User
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // OAuth2User
    @Override
    public String getName() {
        return null;
    }
}
