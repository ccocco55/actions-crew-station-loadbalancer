package com.example.crewstation.controller.member;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.auth.JwtTokenProvider;
import com.example.crewstation.common.enumeration.MemberProvider;
import com.example.crewstation.common.enumeration.MemberRole;
import com.example.crewstation.dto.guest.GuestDTO;
import com.example.crewstation.dto.member.MemberDTO;
import com.example.crewstation.service.guest.GuestService;
import com.example.crewstation.service.member.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.view.RedirectView;

@Controller
@RequestMapping("/member/**")
@RequiredArgsConstructor
@Slf4j
public class MemberController {
    private final MemberService memberService;
    private final GuestService guestService;
    private final JwtTokenProvider jwtTokenProvider;

//    web 회원가입
    @GetMapping("join")
    public String join(MemberDTO memberDTO, Model model) {
        model.addAttribute("memberDTO", memberDTO);

        return "member/web/join";
    }

//    회원가입
    @PostMapping("join")
    public RedirectView join(@ModelAttribute("memberDTO") MemberDTO memberDTO, @RequestParam("file")MultipartFile multipartFile) {
        memberService.join(memberDTO, multipartFile);

        return new RedirectView("/member/login");
    }

//    web 로그인
    @GetMapping("login")
    public String login(MemberDTO memberDTO, GuestDTO guestDTO, Model model) {
        model.addAttribute("memberDTO", memberDTO);
        model.addAttribute("guestDTO", guestDTO);
        return "member/web/login";
    }

// guest 로그인
    @PostMapping("login")
    public RedirectView login(@ModelAttribute("guestDTO") GuestDTO guestDTO) {
        guestService.login(guestDTO);

        return new RedirectView("/guest/order-detail");
    }

//    web sns 회원가입
    @GetMapping("sns/join")
    public String snsJoin(@CookieValue(value = "memberSocialEmail", required = false) String memberSocialEmail,
                          @CookieValue(value = "profile", required = false) String socialProfile,
                          @CookieValue(value = "name", required = false) String memberName,
                          MemberDTO memberDTO, Model model) {
        memberDTO.setMemberSocialEmail(memberSocialEmail);
        memberDTO.setSocialImgUrl(socialProfile);
        memberDTO.setMemberName(memberName);

        model.addAttribute("memberDTO", memberDTO);

        return "member/web/sns/join";
    }

    @PostMapping("sns/join")
    public RedirectView join(@CookieValue(value = "role", required = false) String role,
                             @CookieValue(value = "provider", required = false) String provider, MemberDTO memberDTO,
                             @RequestParam("file")MultipartFile multipartFile) {
        memberDTO.setMemberRole(role.equals("ROLE_MEMBER") ? MemberRole.MEMBER : MemberRole.ADMIN);
        memberDTO.setMemberProvider(MemberProvider.valueOf(provider.toUpperCase()));
        memberService.joinSns(memberDTO, multipartFile);

        jwtTokenProvider.createAccessToken(memberDTO.getMemberSocialEmail(), provider);
        jwtTokenProvider.createRefreshToken(memberDTO.getMemberSocialEmail(), provider);

        return new RedirectView("/");
    }




//    비밀번호 찾기
//    web
    @GetMapping("forgot-password")
    public String changePassword(MemberDTO memberDTO, Model model) {
        model.addAttribute("memberDTO", memberDTO);
        return "member/web/forgot-password";
    }

    @PostMapping("forgot-password")
    public RedirectView changePassword(
            @RequestParam("memberEmail") String memberEmail,
            @RequestParam("memberPassword") String memberPassword
    ) {
        memberService.resetPassword(memberEmail, memberPassword);
        return new RedirectView("/member/reset-password-success");
    }
    
// 비밀벌호 변경 성공
    @GetMapping("reset-password-success")
    public String resetPasswordSuccess() {
        return "member/web/reset-password-success";
    }

    @GetMapping("profile/{memberId}")
    public String profile(@AuthenticationPrincipal CustomUserDetails customUserDetails, Model model) {
        model.addAttribute("memberDTO", customUserDetails);
        return "member/web/profile";

    }

}
