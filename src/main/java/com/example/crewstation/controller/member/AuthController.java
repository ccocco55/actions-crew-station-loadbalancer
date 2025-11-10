package com.example.crewstation.controller.member;

import com.example.crewstation.aop.aspect.annotation.LogReturnStatus;
import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.auth.JwtTokenProvider;
import com.example.crewstation.dto.guest.GuestDTO;
import com.example.crewstation.dto.member.MemberDTO;
import com.example.crewstation.service.member.MemberService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
@RestController
@RequestMapping("/api/auth/**")
@RequiredArgsConstructor
public class
AuthController implements AuthControllerDocs{
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final HttpServletResponse response;
    private final MemberService memberService;
    private final RedisTemplate<String, Object> redisTemplate;

    //    로그인
    @PostMapping("login")
    @LogReturnStatus
    public ResponseEntity<?> login(@RequestBody MemberDTO memberDTO){

        try {
            // 사용자의 이메일과 비밀번호로 인증 시도
            Authentication authentication =
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(memberDTO.getMemberEmail(), memberDTO.getMemberPassword()));

            // 인증 성공 시, SecurityContext에 인증 정보 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 인증된 사용자 정보로부터 액세스 토큰과 리프레시 토큰 생성
            String accessToken = jwtTokenProvider.createAccessToken(((CustomUserDetails) authentication.getPrincipal()).getUserEmail());
            String refreshToken = jwtTokenProvider.createRefreshToken(((CustomUserDetails) authentication.getPrincipal()).getUserEmail());

            // 토큰 정보를 응답 본문에 담기 위한 Map 생성
            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);
            tokens.put("refreshToken", refreshToken);

            // rememberEmail 쿠키 생성 (사용자 이메일 저장용)
            Cookie rememberEmailCookie = new Cookie("rememberEmail", memberDTO.getMemberEmail());

            rememberEmailCookie.setPath("/"); // 모든 경로에서 접근 가능

            // 토큰 정보를 포함한 응답 반환 (HTTP 200 OK)
            return ResponseEntity.ok(tokens);

        } catch(AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "로그인 실패: " + e.getMessage()));
        }
    }

    //   guest 로그인
    @PostMapping("guest-login")
    @LogReturnStatus
    public ResponseEntity<?> guestLogin(@RequestBody GuestDTO guestDTO){
        try {
            // 게스트의 주문번호와 핸드폰번호로 인증 시도
            Authentication authentication =
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(guestDTO.getGuestOrderNumber(), guestDTO.getGuestPhone()));

            // 인증 성공 시, SecurityContext에 인증 정보 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 인증된 사용자 정보로부터 액세스 토큰과 리프레시 토큰 생성
            String accessToken = jwtTokenProvider.createAccessToken(((CustomUserDetails) authentication.getPrincipal()).getGuestOrderNumber());
            String refreshToken = jwtTokenProvider.createRefreshToken(((CustomUserDetails) authentication.getPrincipal()).getGuestOrderNumber());

            // 토큰 정보를 응답 본문에 담기 위한 Map 생성
            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);
            tokens.put("refreshToken", refreshToken);

            // rememberEmail 쿠키 생성 (사용자 이메일 저장용)
            Cookie rememberEmailCookie = new Cookie("rememberEmail", guestDTO.getGuestOrderNumber());

            rememberEmailCookie.setPath("/");

            // 토큰 정보를 포함한 응답 반환 (HTTP 200 OK)
            return ResponseEntity.ok(tokens);

        } catch(AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "로그인 실패: " + e.getMessage()));
        }
    }

    //    로그아웃
    @PostMapping("logout")
    public void logout(@CookieValue(value = "accessToken", required = false) String token) {
        log.info(token);

        // 토큰에서 사용자 이름 추출
        String username = jwtTokenProvider.getUserName(token);

        // 토큰에서 provider 정보 추출 (소셜 로그인 여부 판단용)
        String provider = (String) jwtTokenProvider.getClaims(token).get("provider");

        // provider 값이 없으면 일반 로그인 사용자로 판단
        if(provider == null){
            // Redis에 저장된 리프레시 토큰 삭제
            jwtTokenProvider.deleteRefreshToken(username);

            // 해당 accessToken을 블랙리스트에 등록 (로그아웃 처리)
            jwtTokenProvider.addToBlacklist(token);

        }else{
            // provider가 존재하면 소셜 로그인 사용자로 판단
            jwtTokenProvider.deleteRefreshToken(username, provider);
            jwtTokenProvider.addToBlacklist(token);
        }

// ---------------- 쿠키 삭제 처리 ----------------

        // accessToken 쿠키 삭제 (값 null, 유효기간 0초로 설정)
        Cookie deleteAccessCookie = new Cookie("accessToken", null);
        deleteAccessCookie.setHttpOnly(true);
        deleteAccessCookie.setSecure(false);
        deleteAccessCookie.setPath("/");
        deleteAccessCookie.setMaxAge(0);

        response.addCookie(deleteAccessCookie);

        // refreshToken 쿠키 삭제
        Cookie deleteRefreshCookie = new Cookie("refreshToken", null);
        deleteRefreshCookie.setHttpOnly(true);
        deleteRefreshCookie.setSecure(false);
        deleteRefreshCookie.setPath("/");
        deleteRefreshCookie.setMaxAge(0);

        response.addCookie(deleteRefreshCookie);

        // memberEmail 쿠키 삭제
        Cookie memberEmailCookie = new Cookie("memberEmail", null);
        memberEmailCookie.setHttpOnly(true);
        memberEmailCookie.setSecure(false);
        memberEmailCookie.setPath("/");
        memberEmailCookie.setMaxAge(0);

        response.addCookie(memberEmailCookie);

        // role 쿠키 삭제
        Cookie roleCookie = new Cookie("role", null);
        roleCookie.setHttpOnly(true);
        roleCookie.setSecure(false);
        roleCookie.setPath("/");
        roleCookie.setMaxAge(0);

        response.addCookie(roleCookie);

        // provider 쿠키 삭제
        Cookie deleteProviderCookie = new Cookie("provider", null);
        deleteProviderCookie.setHttpOnly(true);
        deleteProviderCookie.setSecure(false);
        deleteProviderCookie.setPath("/");
        deleteProviderCookie.setMaxAge(0);

        response.addCookie(deleteProviderCookie);

        // ---------------- 캐시 삭제 처리 ----------------

        // 사용자 관련 캐시 삭제 (로그아웃 시 세션/데이터 정리 목적)
        memberService.deleteCache("member");
        memberService.deleteCache("diary");
        memberService.deleteCache("country");
        memberService.deleteCache("purchase");

    }

    //    리프레시 토큰으로 엑세스 토큰 발급
    @GetMapping("refresh")
    public Map<String, String> refresh(@CookieValue(value = "refreshToken", required = false) String token){

        // 리프레시 토큰에서 사용자 이름 추출
        String username = jwtTokenProvider.getUserName(token);

        // Redis 또는 저장소에서 해당 사용자의 리프레시 토큰 조회
        String refreshToken = jwtTokenProvider.getRefreshToken(username);

        // 리프레시 토큰이 없거나 유효하지 않으면 예외 발생
        if(refreshToken == null || !jwtTokenProvider.validateToken(refreshToken)){
            throw new RuntimeException("리프레시 토큰이 유효하지 않습니다.");
        }

        // 리프레시 토큰으로부터 사용자 정보 추출
        CustomUserDetails customUserDetails = (CustomUserDetails) jwtTokenProvider.getAuthentication(refreshToken).getPrincipal();

        // 새로운 액세스 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(customUserDetails.getUserEmail());

        // 기존 리프레시 토큰 삭제 후 새로 발급
        jwtTokenProvider.deleteRefreshToken(username);
        jwtTokenProvider.createRefreshToken(customUserDetails.getUserEmail());

        // 새 액세스 토큰을 응답으로 반환
        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("accessToken", accessToken);

        return tokenMap;
    }

    @GetMapping("/info")
    public MemberDTO getMyInfo(@CookieValue(name = "accessToken", required = false) String token) {

        // 토큰이 없으면 예외 발생
        if (token == null) {
            throw new RuntimeException("토큰이 없습니다.");
        }

        // 블랙리스트에 등록된 토큰인지 확인 (로그아웃된 토큰)
        if (jwtTokenProvider.isTokenBlackList(token)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "로그아웃된 토큰입니다.");
        }

        // 토큰에서 사용자 이메일과 provider 정보 추출
        String memberEmail = jwtTokenProvider.getUserName(token);
        String provider = (String) jwtTokenProvider.getClaims(token).get("provider");

        // 사용자 정보 조회
        MemberDTO member = memberService.getMember(memberEmail, provider);

        return member;
    }

    // 쿠키를 초기화하고 Redis에 저장된 리프레시 토큰을 삭제하는 메서드
    @PostMapping("/reset-cookies")
    public void resetCookies(HttpServletRequest req, HttpServletResponse res){
        Cookie[] cookies = req.getCookies();
        log.info("Cookies are {}", cookies);
        if (cookies != null) {
            boolean accessTokenExists = false;

            // accessToken 쿠키가 존재하는지 확인
            for (Cookie cookie : cookies) {
                if ("accessToken".equals(cookie.getName())) {
                    accessTokenExists = true;
                    break;
                }
            }

            // accessToken이 없으면 모든 쿠키를 삭제
            if (!accessTokenExists) {
                for (Cookie cookie : cookies) {
                    Cookie newCookie = new Cookie(cookie.getName(), null);
                    newCookie.setHttpOnly(true);
                    newCookie.setSecure(false);
                    newCookie.setPath("/");
                    newCookie.setMaxAge(0);
                    res.addCookie(newCookie);
                }
            }
        }

        // Redis에 저장된 모든 리프레시 토큰 키 삭제
        Set<String> keys = redisTemplate.keys("refresh:*");
        if(!keys.isEmpty()){
           redisTemplate.delete(keys);
        }
    }

}












