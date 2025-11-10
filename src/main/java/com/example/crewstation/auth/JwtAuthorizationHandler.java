package com.example.crewstation.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class JwtAuthorizationHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        log.error("AccessDeniedException: {}", accessDeniedException.getMessage());

//            REST 요청인 경우
        if(request.getRequestURI().startsWith("/api/")){
            log.error("accessDeniedException Exception: {}", accessDeniedException.getMessage());
//            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Unauthorized: Access Denied");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("로그인 후 사용 가능");
            response.getWriter().flush();
        }else{
//            모바일 요청인 경우
            if (request.getRequestURI().startsWith("/mobile/")) {
                response.sendRedirect("/mobile/login");
            } else {

//            일반 웹 요청인 경우
                response.sendRedirect("/member/login");
            }
        }
    }
}
