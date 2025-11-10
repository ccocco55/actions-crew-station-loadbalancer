package com.example.crewstation.service.member;

import com.example.crewstation.auth.OAuth2Attribute;
import com.example.crewstation.common.enumeration.MemberProvider;
import com.example.crewstation.repository.member.MemberDAO;
import com.example.crewstation.dto.member.MemberDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final MemberDAO memberDAO;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        // 기본 OAuth2UserService를 사용하여 사용자 정보 로드
        OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);

        // 어떤 소셜 로그인 제공자인지 확인
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // 사용자 식별에 사용할 속성 이름
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        // 소셜 로그인 제공자에 따라 사용자 속성을 표준화하여 처리
        OAuth2Attribute oAuth2Attribute = OAuth2Attribute.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        // 사용자 정보를 Map 형태로 변환
        Map<String, Object> memberAttribute = oAuth2Attribute.convertToMap();

        // 사용자 이메일 추출
        String email = (String) memberAttribute.get("email");

        // 이메일과 provider를 기준으로 회원 여부 조회
        Optional<MemberDTO> foundMember = memberDAO.findBySnsEmail(email, MemberProvider.getStatusFromValue(registrationId));
        if(foundMember.isEmpty()) {
//            회원이 존재하지 않을 경우,
            memberAttribute.put("exist", false);
            return new DefaultOAuth2User(
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_MEMBER")),
                    memberAttribute, "email");
        }
        memberAttribute.put("exist", true);
        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority("ROLE_" + foundMember.get().getMemberRole())),
                memberAttribute, "email");
    }
}
