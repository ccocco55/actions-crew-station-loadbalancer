package com.example.crewstation.service.member;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.common.enumeration.MemberProvider;
import com.example.crewstation.dto.guest.GuestDTO;
import com.example.crewstation.dto.member.MemberDTO;
import com.example.crewstation.repository.guest.GuestDAO;
import com.example.crewstation.repository.member.MemberDAO;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberDAO memberDAO;
    private final GuestDAO guestDAO;
    private final HttpServletRequest request;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String provider = null; // 소셜 로그인 제공자 정보
        MemberDTO memberDTO = null; // 게스트 주문번호

        // 요청에 포함된 쿠키에서 provider 값을 추출 (소셜 로그인 여부 확인)
        if(request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if("provider".equals(cookie.getName())){
                    provider = cookie.getValue();
                }
            }
        }

        // provider 값이 없으면 일반 로그인 또는 게스트 로그인으로 판단
        if(provider == null){

            if (username.contains("@")) {
                // 이메일 형식이면 일반 회원으로 간주하고 DB에서 조회
                memberDTO = memberDAO.findByMemberEmail(username)
                        .orElseThrow(() -> new UsernameNotFoundException("소유자를 찾을 수 없습니다."));
            } else {
                // 이메일이 아니면 게스트 주문번호로 간주하고 조회
                GuestDTO guestDTO = guestDAO.selectGuestByOrderNumber(username)
                        .orElseThrow(() -> new UsernameNotFoundException("게스트를 찾을 수 없습니다."));
                // 게스트 정보로 CustomUserDetails 객체 생성 후 반환
                return new CustomUserDetails(guestDTO);

            }
        }else{
            // provider 값이 존재하면 소셜 로그인 사용자로 간주하고 조회
            memberDTO = memberDAO.findBySnsEmail(username, MemberProvider.getStatusFromValue(provider))
                    .orElseThrow(() -> new UsernameNotFoundException("소유자를 찾을 수 없습니다."));
        }

        // 조회된 회원 정보로 CustomUserDetails 객체 생성 후 반환
        return new CustomUserDetails(memberDTO);
    }
}















