package com.example.crewstation.controller.member;

import com.example.crewstation.auth.JwtTokenProvider;
import com.example.crewstation.common.enumeration.MemberProvider;
import com.example.crewstation.common.enumeration.MemberRole;
import com.example.crewstation.dto.guest.GuestDTO;
import com.example.crewstation.dto.member.MemberDTO;
import com.example.crewstation.service.guest.GuestService;
import com.example.crewstation.service.member.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.view.RedirectView;

@Controller
@RequestMapping("/mobile/**")
@RequiredArgsConstructor
@Slf4j
public class MobileMemberController {
    private final MemberService memberService;
    private final GuestService guestService;
    private final JwtTokenProvider jwtTokenProvider;


//    mobile 회원가입
    @GetMapping("join")
    public String mobileJoin(MemberDTO memberDTO, GuestDTO guestDTO, Model model) {
        model.addAttribute("memberDTO", memberDTO);
        model.addAttribute("guestDTO", guestDTO);

        return "member/mobile/join";
    }

    @PostMapping("join")
    public RedirectView mobileJoin(@ModelAttribute("memberDTO") MemberDTO memberDTO, @RequestParam("file")MultipartFile multipartFile) {
        memberService.join(memberDTO, multipartFile);

        return new RedirectView("/mobile/login");
    }

//    mobile 로그인
    @GetMapping("login")
    public String mobileLogin(MemberDTO memberDTO, GuestDTO guestDTO, Model model) {
        model.addAttribute("memberDTO", memberDTO);
        model.addAttribute("guestDTO", guestDTO);
        return "member/mobile/login";
    }

//    게스트 로그인
    @PostMapping("login")
    public RedirectView mobileLogin(@ModelAttribute("guestDTO") GuestDTO guestDTO) {
        guestService.login(guestDTO);

        
        return new RedirectView("/guest/order-detail");
    }

//    mobile sns 회원가입
    @GetMapping("sns/join")
    public String mobileJoin(@CookieValue(value = "memberSocialEmail", required = false) String memberSocialEmail,
                          @CookieValue(value = "profile", required = false) String socialProfile,
                          @CookieValue(value = "name", required = false) String memberName,
                          MemberDTO memberDTO, Model model) {
        memberDTO.setMemberSocialEmail(memberSocialEmail);
        memberDTO.setSocialImgUrl(socialProfile);
        memberDTO.setMemberName(memberName);

        model.addAttribute("memberDTO", memberDTO);

        return "member/mobile/sns/join";
    }

    @PostMapping("sns/join")
    public RedirectView mobileJoin(@CookieValue(value = "role", required = false) String role,
                             @CookieValue(value = "provider", required = false) String provider, MemberDTO memberDTO,
                             @RequestParam("file")MultipartFile multipartFile) {
        memberDTO.setMemberRole(role.equals("ROLE_MEMBER") ? MemberRole.MEMBER : MemberRole.ADMIN);
        memberDTO.setMemberProvider(MemberProvider.valueOf(provider.toUpperCase()));
        memberService.joinSns(memberDTO, multipartFile);

        jwtTokenProvider.createAccessToken(memberDTO.getMemberSocialEmail(), provider);
        jwtTokenProvider.createRefreshToken(memberDTO.getMemberSocialEmail(), provider);

        return new RedirectView("/gifts");
    }





//    mobile 비밀번호 변경
    @GetMapping("forgot-password")
    public String mobileChangePassword(MemberDTO memberDTO, Model model) {
        model.addAttribute("memberDTO", memberDTO);
        return "member/mobile/forgot-password";
    }

    @PostMapping("forgot-password")
    public RedirectView mobileChangePassword(
            @RequestParam("memberEmail") String memberEmail,
            @RequestParam("memberPassword") String memberPassword
    ) {
        memberService.resetPassword(memberEmail, memberPassword);
        return new RedirectView("/mobile/reset-password-success");
    }

// 비밀벌호 변경 성공
    @GetMapping("reset-password-success")
    public String mobileResetPasswordSuccess() {
        return "member/mobile/reset-password-success";
    }
}
