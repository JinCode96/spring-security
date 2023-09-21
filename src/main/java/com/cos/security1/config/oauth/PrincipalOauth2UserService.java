package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FaceBookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * OAuth 로그인 후처리 담당 클래스
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    /**
     * 구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
//        log.info("getClientRegistration={}", userRequest.getClientRegistration());
//        log.info("getTokenValue={}", userRequest.getAccessToken().getTokenValue()); // 엑세스 토큰

        OAuth2User oAuth2User = super.loadUser(userRequest);
//        log.info("oAuth2User.getAttributes={}", oAuth2User.getAttributes());

        // 회원가입 진행
        OAuth2UserInfo oAuth2UserInfo = null;

        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {

            log.info("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());

        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {

            log.info("페이스북 로그인 요청");
            oAuth2UserInfo = new FaceBookUserInfo(oAuth2User.getAttributes());

        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {

            log.info("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));

        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId; // username 충돌 방지
        String email = oAuth2UserInfo.getEmail();
        String password = bCryptPasswordEncoder.encode("겟인데어"); // 크게 의미는 없는 로직
        String role = "USER";

        // 회원가입 진행
        User userEntity = null;
        if (userRepository.findByUsername(username) == null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }
        log.info("userEntity={}", userEntity);

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes()); // PrincipalDetails 반환
    }
}
