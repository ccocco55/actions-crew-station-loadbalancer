package com.example.crewstation.controller.ask;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.domain.ask.AskVO;
import com.example.crewstation.service.ask.AskService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

@Controller
@RequestMapping("/ask/**")
@RequiredArgsConstructor
@Slf4j
public class AskController {
    private final AskService askService;

    @GetMapping("register")
    public String goToRegisterForm(@AuthenticationPrincipal CustomUserDetails customUserDetails, Model model) {
        model.addAttribute("memberId", customUserDetails.getId());
        return "ask/register";
    }

    @PostMapping("register")
    public RedirectView register(AskVO askVO, RedirectAttributes redirectAttributes){
        log.info(askVO.toString());
        askService.register(askVO);
        redirectAttributes.addAttribute("id",askVO.getId());
        return new RedirectView("/mypage/my-diary/inquiry");
    }

}
