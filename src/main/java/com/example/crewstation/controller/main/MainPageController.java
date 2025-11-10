package com.example.crewstation.controller.main;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.dto.accompany.AccompanyDTO;
import com.example.crewstation.dto.banner.BannerDTO;
import com.example.crewstation.dto.crew.CrewDTO;
import com.example.crewstation.dto.diary.DiaryDTO;
import com.example.crewstation.dto.gift.GiftDTO;
import com.example.crewstation.service.accompany.AccompanyService;
import com.example.crewstation.service.banner.BannerService;
import com.example.crewstation.service.crew.CrewService;
import com.example.crewstation.service.diary.DiaryService;
import com.example.crewstation.service.gift.GiftService;
import com.example.crewstation.util.Search;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequestMapping("/")
@RequiredArgsConstructor
@Slf4j
public class MainPageController {
    private final CrewService crewService;
    private final BannerService bannerService;
    private final DiaryService diaryService;
    private final GiftService giftService;
    private final AccompanyService accompanyService;

    @GetMapping
    public String getMainPage(Model model, @AuthenticationPrincipal CustomUserDetails user) {

        Long memberId = (user != null) ? user.getId() : null;

//        List<CrewDTO> crews = crewService.getCrews();
        List<DiaryDTO> diaries = diaryService.selectDiaryList(memberId,4);
        List<BannerDTO> banners = bannerService.getBanners(5);
        List<GiftDTO> gifts = giftService.getGift(4);
        log.info("{}:::::::",gifts);
//        List<AccompanyDTO> accompanies = accompanyService.getAccompanies(4);



        model.addAttribute("banners", banners);
//        log.info("banners = {}", banners);
//        model.addAttribute("crews", crews);
//        log.info("crews = {}", crews);
        model.addAttribute("diaries", diaries);
        log.info("diaries = {}", diaries);
//        model.addAttribute("accompanies", accompanies);
//        log.info("accompanies = {}", accompanies);
        model.addAttribute("gifts", gifts);
//        log.info("gifts = {}", gifts);




        return "main-page/main";
    }

    @GetMapping("/company")
    public String getCompanyPage(Model model) {

        return "main-page/company-info";
    }
}

