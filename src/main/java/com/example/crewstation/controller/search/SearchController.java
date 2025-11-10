package com.example.crewstation.controller.search;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.dto.accompany.AccompanyCriteriaDTO;
import com.example.crewstation.dto.crew.CrewCriteriaDTO;
import com.example.crewstation.dto.crew.CrewDTO;
import com.example.crewstation.dto.diary.DiaryCriteriaDTO;
import com.example.crewstation.dto.gift.GiftCriteriaDTO;
import com.example.crewstation.service.accompany.AccompanyService;
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
@RequestMapping("/search")
@RequiredArgsConstructor
@Slf4j
public class SearchController {
    private final CrewService crewService;
    private final DiaryService diaryService;
    private final GiftService giftService;
    private final AccompanyService accompanyService;

    @GetMapping("/total")
    public String getSearch(Search search,
                            @AuthenticationPrincipal CustomUserDetails customUserDetails,
                            Model model) {

        log.info("통합 검색 요청 - keyword: {}", search.getKeyword());

//        CrewCriteriaDTO crews = crewService.getSearchCrews(search);
        DiaryCriteriaDTO diaries = diaryService.countDiaryImg(search,customUserDetails);
//        AccompanyCriteriaDTO accompanies = accompanyService.getSearchAccompanies(search);
        GiftCriteriaDTO gifts = giftService.getGifts(search,customUserDetails);


        model.addAttribute("keyword", search.getKeyword());
//        model.addAttribute("crews", crews);
        model.addAttribute("diaries", diaries);
//        model.addAttribute("accompanies", accompanies);
        model.addAttribute("gifts", gifts);



        return "main-page/total-search";


    }
}







