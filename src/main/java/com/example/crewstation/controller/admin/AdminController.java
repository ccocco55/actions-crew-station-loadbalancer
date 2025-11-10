package com.example.crewstation.controller.admin;

import com.example.crewstation.common.enumeration.MemberRole;
import com.example.crewstation.dto.banner.BannerDTO;
import com.example.crewstation.dto.crew.CrewDTO;
import com.example.crewstation.dto.member.MemberDTO;
import com.example.crewstation.service.member.MemberService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

@Controller
@RequestMapping("/admin")
public class AdminController {
    private final MemberService memberService;

    public AdminController(MemberService memberService) {
        this.memberService = memberService;
    }

    @GetMapping("")
    public String goAdminPage(){

        return "admin/main";
    }

    @GetMapping("/join")
    public String goJoinPage(MemberDTO memberDTO, Model model){
        model.addAttribute("memberDTO",memberDTO);

        return "admin/join";
    }

    @PostMapping("/join")
    public RedirectView adminJoin(@ModelAttribute("memberDTO") MemberDTO memberDTO) {
        memberDTO.setMemberRole(MemberRole.ADMIN);
        memberService.joinAdmin(memberDTO);

        return new RedirectView("/admin/login");
    }


    @GetMapping("login")
    public String goLoginPage(MemberDTO memberDTO, Model model){
        model.addAttribute("memberDTO",memberDTO);

        return "admin/login";
    }







}
