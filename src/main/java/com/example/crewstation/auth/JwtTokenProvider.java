package com.example.crewstation.auth;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.DigestUtils;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {
    @Value("${jwt.secret}")
    private String secretKey;
    private Key key;
    private final RedisTemplate<String, Object> redisTemplate;
    private final HttpServletResponse response;
    private final UserDetailsService userDetailService;

    private static final String REFRESH_TOKEN_PREFIX = "refresh:";
    private static final String BLACKLIST_PREFIX = "blacklist:";

    @PostConstruct
    protected void init() {
        // Base64로 인코딩된 문자열 형태의 secretKey를 디코딩하여 바이트 배열로 변환
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        // 디코딩된 바이트 배열을 기반으로 HMAC-SHA 알고리즘을 사용하는 서명 키 생성
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

//    액세스 토큰 생성
    public String createAccessToken(String username) {
        long ACCESS_TOKEN_VALIDITY = 1000L * 60 * 10;
        String accessToken = Jwts.builder()
//                토큰 소유자
                .setSubject(username)
//                토큰에 저장할 정보
                .claim("memberEmail", username)
//                발급 시간
                .setIssuedAt(new Date())
//                만료 시간
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true); // JavaScript에서 접근할 수 없도록 설정하여 XSS 공격 방지
        accessTokenCookie.setSecure(false); // HTTP/HTTPS 모두에서 쿠키 전송 가능
        accessTokenCookie.setPath("/"); // 쿠키가 모든 경로에서 유효하도록 설정
        accessTokenCookie.setMaxAge(60 * 10); // 10분
        response.addCookie(accessTokenCookie); // 설정한 쿠키를 응답에 추가하여 클라이언트로 전송

        return accessToken;
    }
//    OAuth2 accesstoken
    public String createAccessToken(String username, String provider) {
        long ACCESS_TOKEN_VALIDITY = 1000L * 60 * 10;
        String accessToken = Jwts.builder()
//                토큰 소유자
                .setSubject(username)
//                토큰에 저장할 정보
                .claim("memberEmail", username)
                .claim("provider", provider)
//                발급 시간
                .setIssuedAt(new Date())
//                만료 시간
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(60 * 10); // 10분
        response.addCookie(accessTokenCookie);

        return accessToken;
    }
//    JWT 토큰 유효성 검증
    public boolean validateToken(String token) {
        try {
            // JWT 파서 생성 후 서명 키를 설정하고 토큰을 파싱하여 클레임을 검증
            Jwts.parserBuilder()
                    .setSigningKey(key).build()
                    .parseClaimsJws(token);
            // 예외가 발생하지 않으면 유효한 토큰으로 판단
            return true;
        } catch (JwtException | IllegalArgumentException e) {
//            ExpiredJwtException: 토큰 만료
//            UnsupportedJwtException: 지원하지 않는 JWT 형식
//            MalformedJwtException: JWT 형식이 잘못되었을 때
//            SignatureException: 서명이 일치하지 않을 때(위조된 토큰)
//            IllegalArgumentException: null, 빈 문자열 등 잘못된 파라미터일 때
            return false;
        }
    }

//    토큰 만료 검사
    public boolean isTokenExpired(String token){
        try {
            // 토큰을 파싱하여 클레임(Claims) 객체를 추출
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key) // 서명 키 설정
                    .build()
                    .parseClaimsJws(token) // 토큰 파싱 및 서명 검증
                    .getBody(); // 클레임 정보 추출

            // 클레임에서 만료 시간 추출
            Date expiration = claims.getExpiration();

            // 현재 시간과 비교하여 만료 여부 반환
            return expiration.before(new Date());
        } catch (ExpiredJwtException e){
            return true;
        } catch (Exception e){
            return true;
        }
    }

//    인증 정보 객체 생성
    public Authentication getAuthentication(String token) {
        String username = getUserName(token);
//        DB 조회
        UserDetails userDetails = userDetailService.loadUserByUsername(username);
//        Spring Security가 이해할 수 있는 Authentication 객체로 감싸기
//        JWT 인증에서는 이미 토큰 자체가 인증 수단이기 때문에 비밀번호를 ""로 전달해도 아무 문제 없다.
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

//    토큰 소유자 추출
    public String getUserName(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

//    리프레시 토큰 생성
    public String createRefreshToken(String username) {
        long REFRESH_TOKEN_VALIDITY = 1000L * 60 * 60 * 24 * 1;
        String refreshToken = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        redisTemplate.opsForValue().set(
                 username.contains("@") ? REFRESH_TOKEN_PREFIX + username : "guest_" + REFRESH_TOKEN_PREFIX + username,
                refreshToken,
                REFRESH_TOKEN_VALIDITY,
                TimeUnit.MILLISECONDS
        );

        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(60 * 60 * 24 * 1); // 1일
        response.addCookie(refreshTokenCookie);

        return refreshToken;
    }

//    OAuth2
    public String createRefreshToken(String username, String provider) {
        long REFRESH_TOKEN_VALIDITY = 1000L * 60 * 60 * 24 * 1;
        String refreshToken = Jwts.builder()
                .setSubject(username)
                .claim("provider", provider)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        redisTemplate.opsForValue().set(
                REFRESH_TOKEN_PREFIX + provider + "_" + username,
                refreshToken,
                REFRESH_TOKEN_VALIDITY,
                TimeUnit.MILLISECONDS
        );

        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(60 * 60 * 24 * 1); // 1일
        response.addCookie(refreshTokenCookie);

        return refreshToken;
    }
//    쿠키와 Redis에서 각 RefreshToken을 가져와서 비교
    public boolean checkRefreshTokenBetweenCookieAndRedis(String username, String cookieRefreshToken){
        String redisRefreshToken = getRefreshToken(username);
        return redisRefreshToken.equals(cookieRefreshToken);
    }

    public boolean checkRefreshTokenBetweenCookieAndRedis(String username, String provider, String cookieRefreshToken){
        String redisRefreshToken = getRefreshToken(username, provider);
        return redisRefreshToken.equals(cookieRefreshToken);
    }

//    리프레시 토큰 삭제
    public void deleteRefreshToken(String username) {
        log.info("{}", redisTemplate.delete((username.contains("@") ? "" : "guest_") + REFRESH_TOKEN_PREFIX + username));
    }

    public void deleteRefreshToken(String username, String provider) {
        log.info("{}", redisTemplate.delete(REFRESH_TOKEN_PREFIX + provider + "_" + username));
    }

//    refresh token 조회
    public String getRefreshToken(String username) {
        return (String) redisTemplate.opsForValue().get((username.contains("@") ? "" : "guest_") + REFRESH_TOKEN_PREFIX + username);
    }

    public String getRefreshToken(String username, String provider) {
        log.info("#########: {}, {}", provider, username);
        return (String) redisTemplate.opsForValue().get(REFRESH_TOKEN_PREFIX + provider + "_" + username);
    }

//    JWT 토큰에서 클레임 정보 추출
    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

//    클라이언트 요청에서 액세스 토큰 추출
    public String parseTokenFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        log.info("{}: ", bearerToken);
//        Authorization: Bearer fnmWsEiofBMIO029hfinDEo...
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }

        if(request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if("accessToken".equals(cookie.getName())){
                    return cookie.getValue();
                }
            }
        }

        return null;
    }


//    로그아웃 블랙 리스트 메소드
    public void addToBlacklist(String token){
        try {
            String tokenId = getBlackListTokenKey(token);
            Claims claims = getClaims(token);
            long gap = claims.getExpiration().getTime() - System.currentTimeMillis();
            if (gap > 0) {
                String blackListKey = BLACKLIST_PREFIX + tokenId;
                redisTemplate.opsForValue().set(
                        blackListKey,
                        "blacklisted",
                        gap,
                        TimeUnit.MILLISECONDS
                );
            }
        } catch (Exception e) {
            throw new RuntimeException("토큰을 블랙리스트에 추가하는데에 실패했습니다.");
        }

    }

//    블랙 리스트 조회
    public boolean isTokenBlackList(String token){
        try {
            String tokenId = getBlackListTokenKey(token);
            String blacklistKey = BLACKLIST_PREFIX + tokenId;
            Boolean hasKey = redisTemplate.hasKey(blacklistKey);
            return hasKey;
        } catch (Exception e) {
            log.error("블랙리스트 확인 중 오류 발생: {}", e.getMessage());
            return true;
        }
    }

//    MD5 해시값 생성
    private String getBlackListTokenKey(String token) {
//        이렇게 하면 긴 토큰 문자열을 짧고 고유한 키로 관리 가능(메모리 효율)
        return DigestUtils.md5DigestAsHex(token.getBytes());
    }
}
















