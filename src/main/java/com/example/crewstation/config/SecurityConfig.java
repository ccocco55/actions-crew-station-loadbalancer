package com.example.crewstation.config;

import com.example.crewstation.auth.*;
import com.example.crewstation.auth.JwtAuthenticationFilter;
import com.example.crewstation.auth.JwtAuthenticationHandler;
import com.example.crewstation.auth.JwtAuthorizationHandler;
import com.example.crewstation.common.enumeration.MemberRole;
import com.example.crewstation.service.member.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

// 클라이언트 -> 로그인 요청, AuthController
// AuthController -> 인증 요청, AuthenticationManager
// AuthenticationManager -> 사용자 확인, UserDetailService
// UserDetailService -> DB 조회, 데이터베이스
// AuthenticationManager -> 인증 완료, AuthController
// AuthController -> JWT 토큰 생성, JwtTokenProvider
// JwtTokenProvider -> 토큰 리턴, AuthController
// AuthController -> 토큰 전달, 클라이언트
// 클라이언트 -> 토큰과 함께 요청, JwtAuthenticationFilter
// JwtAuthenticationFilter -> 토큰 검증, JwtTokenProvider

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
    private final JwtAuthenticationHandler jwtAuthenticationHandler;
    private final JwtAuthorizationHandler jwtAuthorizationHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final OAuth2FailureHandler oAuth2FailureHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
//                주로 REST API 서버에서는 세션 없이 JWT를 쓰기 때문에 CSRF가 필요 없어서 비활성화 설정
//                Cross-Site Request Forgery, 사이트 간 요청 위조
//                공격의 한 종류로, 공격자가 사용자의 인증된 상태(로그인 세션 등)를 이용해서
//                사용자가 의도하지 않은 요청을 특정 웹사이트에 보내게 만드는 공격
                .csrf(AbstractHttpConfigurer::disable)
//                세션 정책을 무상태(stateless) 로 설정, 서버에 세션을 저장하지 않기 때문
//                상태 존재: 서버가 클라이언트의 상태를 기억하는 경우
//                상태 없음: 서버가 클라이언트의 상태를 저장하지 않는 경우
//                JWT 기반 인증은 무상태(stateless) 인증 방식ß
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/login/oauth2/**",
                                "/notice/detail/**",
                                "/api/auth/guest-login",
                                "/admin/login",
                                "/api/payment/{purchaseId:\\d+}",
                                "/error",
                                "/api/auth/**",
                                "/api/admin/auth/**",
                                "/member/join",
                                "/member/login",
                                "/member/sns/join",
                                "/member/profile/{memberId:\\d+}",
                                "/api/member/profile/{memberId:\\d+}",
                                "/api/diaries/profile/{memberId:\\d+}",
                                "/mobile/join",
                                "/mobile/login",
                                "/mobile/sns/join",
                                "/member/forgot-password",
                                "/mobile/forgot-password",
                                "/api/member/**",
                                "/member/reset-password-success",
                                "/mobile/reset-password-success",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/",
                                "/diaries",
                                "/diaries/detail/**",
                                "/api/diaries",
                                "/api/replies/{postId:\\d+}",
                                "/gifts",
                                "/gifts/detail/{postId:\\d+}",
                                "/api/gifts",
                                "/company",
                                "/search",
                                "/ask/register",
                                "/notice/notice",
                                "/notice/notice-detail",
                                "/guest/order-detail",
                                "/api/guest/order-detail/{guestOrderNumber:\\d+}")
                        .permitAll()
                        .requestMatchers(HttpMethod.POST,
                                "/diaries/write",
                                "/api/likes/**",
                                "/api/report/**",
                                "/diaries/{postId:\\d+}",
                                "/gifts/write",
                                "/gifts/{postId:\\d+}")
                        .authenticated()
                        .requestMatchers(HttpMethod.GET,
                                "/mypage/my-activities",
                                "/diaries/write",
                                "/gifts/write",
                                "/diaries/delete/{postId:\\d+}",
                                "/gifts/delete/{postId:\\d+}",
                                "/gifts/{postId:\\d+}",
                                "/diaries/{postId:\\d+}")
                        .authenticated()
                        .requestMatchers(HttpMethod.PUT,
                                "/api/diaries/secret/{diaryId:\\d+}",
                                "/api/replies")
                        .authenticated()
                        .requestMatchers(HttpMethod.DELETE,
                                "/api/replies")
                        .authenticated()
                        .requestMatchers("/admin/**").hasRole(MemberRole.ADMIN.name())
                        .anyRequest().authenticated()
                )
                // ExceptionHandling 설정(인증, 인가) 추가
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(jwtAuthenticationHandler)
                                .accessDeniedHandler(jwtAuthorizationHandler)
                )
                .oauth2Login(oauth -> oauth
                        .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
                        .successHandler(oAuth2SuccessHandler)
                        .failureHandler(oAuth2FailureHandler)
                )
                //                스프링 시큐리티 필터 체인에서 특정 필터 앞에 내가 만든 필터를 삽입
                //                UsernamePasswordAuthenticationFilter.class(아이디, 비밀번호 form 로그인) 이전에
                //                jwtAuthenticationFilter를 먼저 실행
                //                form 로그인 인증 전에 토큰 인증을 먼저 처리해서 SecurityContext에 인증 정보를 채우기 위해
                //                이로 인해 form 로그인 없이 JWT 토큰으로 인증이 가능
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
//        회원가입 시 비밀번호를 저장할 때, 이 PasswordEncoder로 암호화해서 저장하고,
//        로그인 시에도 입력 비밀번호를 같은 방식으로 암호화해서 DB에 저장된 해시와 비교
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
//        인증 성공 시 Authentication 객체를 만들어 반환
        return configuration.getAuthenticationManager();
    }
}