package com.example.crewstation.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
//      요청 헤더에서 JWT 액세스 토큰을 추출
        String token = jwtTokenProvider.parseTokenFromHeader(request);

//      액세스  토큰이 존재하는 경우
        if(token != null) {
            log.info("Token found: {}", token);
            // 토큰 유효성 검사
            if(jwtTokenProvider.validateToken(token)){
                log.info("Token is valid");
                // 블랙리스트에 등록된 토큰인지 확인
                if(jwtTokenProvider.isTokenBlackList(token)){
                    log.info("Token is blacklisted");
                    // 인증 실패 응답 반환
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "This token is logout token");
                    return;
                }
                // 토큰으로부터 인증 객체 생성
                UsernamePasswordAuthenticationToken authentication =
                        (UsernamePasswordAuthenticationToken) jwtTokenProvider.getAuthentication(token);
                // 인증 객체에 요청 정보를 추가
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContext에 인증 정보 설정
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("Authentication:"+authentication);
                log.info("Authentication name: {}", authentication.getName());
                log.info("Authentication details: {}", authentication.getAuthorities());
                log.info("Authentication in SecurityContext: {}", SecurityContextHolder.getContext().getAuthentication());
            } else {
                log.warn("Token is not valid");
            }
        } else {
            // 액세스 토큰이 없는 경우, 쿠키에서 리프레시 토큰과 provider 정보 추출
            String cookieRefreshToken = null;
            String provider = null;

            if(request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if("refreshToken".equals(cookie.getName())){
                        cookieRefreshToken = cookie.getValue();
                    }
                    if("provider".equals(cookie.getName())){
                        provider = cookie.getValue();
                    }
                }
            }
            // 리프레시 토큰이 존재하는 경우
            if(cookieRefreshToken != null) {
                // 리프레시 토큰에서 사용자 이름 추출
                String username = jwtTokenProvider.getUserName(cookieRefreshToken);
                String accessToken = null;

                // Redis에 저장된 리프레시 토큰과 쿠키의 토큰이 일치하는지 확인
                boolean checkRefreshToken = provider != null ? jwtTokenProvider.checkRefreshTokenBetweenCookieAndRedis(username, provider, cookieRefreshToken)
                        : jwtTokenProvider.checkRefreshTokenBetweenCookieAndRedis(username, cookieRefreshToken);

                // 리프레시 토큰이 유효하고 일치하는 경우
                if (checkRefreshToken) {
                    if (jwtTokenProvider.validateToken(cookieRefreshToken)) {

                        // 리프레시 토큰으로부터 사용자 정보 추출
                        CustomUserDetails customUserDetails = (CustomUserDetails) jwtTokenProvider.getAuthentication(cookieRefreshToken).getPrincipal();

                        // 이메일 기반 사용자와 게스트 사용자 구분
                        if(username.contains("@")){
                            accessToken = jwtTokenProvider.createAccessToken(provider == null ? customUserDetails.getUserEmail() : customUserDetails.getMemberSocialEmail());
                            jwtTokenProvider.createRefreshToken(provider == null ? customUserDetails.getUserEmail() : customUserDetails.getMemberSocialEmail());
                        }else{
                            accessToken = jwtTokenProvider.createAccessToken(customUserDetails.getGuestOrderNumber());
                            jwtTokenProvider.createRefreshToken(customUserDetails.getGuestOrderNumber());
                        }

                        // 새로 발급한 액세스 토큰을 응답 헤더에 설정하고 현재 URI로 리다이렉트
                        response.setHeader("Authorization", "Bearer " + accessToken);
                        response.sendRedirect(request.getRequestURI());
                        return;
                    }
                }
            }else {
                log.warn("No token found");
            }
        }

//        이 코드를 호출해서 필터 체인에 있는 다음 필터에게 요청과 응답 처리를 넘김
//        만약 doFilter 메소드를 호출하지 않으면, 필터 체인의 다음 필터는 실행되지 않고 요청이 멈춤
        filterChain.doFilter(request, response);
    }
}
