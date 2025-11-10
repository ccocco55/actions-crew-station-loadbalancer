package com.example.crewstation.controller.mypage;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.auth.JwtTokenProvider;
import com.example.crewstation.dto.member.ModifyDTO;
import com.example.crewstation.dto.member.MySaleDetailDTO;
import com.example.crewstation.dto.member.MySaleListCriteriaDTO;
import com.example.crewstation.dto.member.MySaleListDTO;
import com.example.crewstation.dto.purchase.PurchaseListCriteriaDTO;
import com.example.crewstation.service.member.MemberService;
import com.example.crewstation.service.purchase.PurchaseService;
import com.example.crewstation.util.Criteria;
import com.example.crewstation.util.ScrollCriteria;
import com.example.crewstation.util.Search;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.view.RedirectView;

import java.util.List;

@Controller
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/mypage/**")
public class MypageController {

    private final PurchaseService purchaseService;
    private final MemberService memberService;
    private final JwtTokenProvider jwtTokenProvider;

    // 마이페이지 -> 내가 좋아요한 일기 목록 화면 & 내가 댓글 단 일기 목록 화면
    @GetMapping("/my-activities")
    public String loadMyActivitiesPage() {
        log.info("마이페이지 - 좋아요한 일기 화면 요청");
        return "mypage/my-activities";
    }

    // 마이페이지 -> 나의 구매내역 목록
    @GetMapping("/purchase-list")
    public String getPurchaseList(@AuthenticationPrincipal CustomUserDetails customUserDetails,
                                  @RequestParam(defaultValue = "1") int page,
                                  @RequestParam(defaultValue = "10") int size,
                                  @RequestParam(required = false) String keyword,
                                  Model model) {

        Long memberId = customUserDetails.getId();

        ScrollCriteria scrollCriteria = new ScrollCriteria(page, size);
        Search search = new Search();
        search.setKeyword(keyword);

        PurchaseListCriteriaDTO result = purchaseService.getPurchaseListByMemberId(memberId, scrollCriteria, search);

        model.addAttribute("result", result);
        model.addAttribute("purchaseList", result.getPurchaseListDTOs());
        model.addAttribute("criteria", result.getScrollcriteria());
        model.addAttribute("search", result.getSearch());

        log.info("memberId={}, keyword={}, page={}, size={}", memberId, keyword, page, size);
        log.info("otal={}, hasMore={}", scrollCriteria.getTotal(), scrollCriteria.isHasMore());

        return "mypage/purchase-list";
    }

    // 마이페이지 - 구매 상세 페이지
    @GetMapping("/purchase-detail/{paymentStatusId}")
    public String loadMyPurchaseDetailPage(@PathVariable("paymentStatusId") Long paymentStatusId, Model model) {
        model.addAttribute("paymentStatusId", paymentStatusId);
        return "mypage/purchase-detail";
    }


    // 마이페이지 -> 나의 판매내역 목록
    @GetMapping("/sale-list")
    public String getSaleList(@AuthenticationPrincipal CustomUserDetails customUserDetails,
                              @RequestParam(defaultValue = "1") int page,
                              @RequestParam(defaultValue = "10") int size,
                              @RequestParam(required = false) String keyword,
                              Model model) {

        Long memberId = customUserDetails.getId();

        Criteria criteria = new Criteria(page, size);
        Search search = new Search();
        search.setKeyword(keyword);

        MySaleListCriteriaDTO result = memberService.getSaleListByMemberId(memberId, criteria, search);

        model.addAttribute("result", result);
        model.addAttribute("saleList", result.getMySaleListDTOs());
        model.addAttribute("criteria", result.getCriteria());
        model.addAttribute("search", result.getSearch());

        log.info("memberId={}, keyword={}, page={}, size={}", memberId, keyword, page, size);
        log.info("total={}, hasMore={}", criteria.getTotal(), criteria.isHasMore());

        return "mypage/sale-list";
    }

    // 마이페이지 - 판매 상세 페이지
    @GetMapping("/sale-detail/{paymentStatusId}")
    public String loadMySaleDetailPage(@PathVariable("paymentStatusId") Long paymentStatusId, Model model) {
        model.addAttribute("paymentStatusId", paymentStatusId);
        return "mypage/sale-detail";
    }

    //  내 정보 수정 페이지 조회
    @GetMapping("/modify")
    public String loadMyInfoPage(@AuthenticationPrincipal CustomUserDetails user, Model model) {
        ModifyDTO modifyDTO = memberService.getMemberInfo(user);
        model.addAttribute("modifyDTO", modifyDTO);
        return "mypage/modify";
    }

    //  내 정보 수정 페이지에서 수정
    @PostMapping("/modify")
    public String modify(@AuthenticationPrincipal CustomUserDetails user,
                         @ModelAttribute ModifyDTO modifyDTO,
                         @RequestParam(value = "profileFile", required = false) MultipartFile profileFile,
                         Model model) {
        try {
            modifyDTO.setMemberId(user.getId());
            memberService.updateMyInfo(modifyDTO, profileFile);
            log.info("회원 정보 수정 완료 - memberId={}", user.getId());
            return "redirect:/mypage/modify";
        } catch (Exception e) {
            log.error("회원 정보 수정 실패", e);
            model.addAttribute("error", "정보 수정 중 오류가 발생했습니다.");
            return "mypage/modify";
        }
    }

//  회원 탈퇴(비활성화)
    @GetMapping("/delete/confirm")
    public RedirectView deleteMember(@AuthenticationPrincipal CustomUserDetails customUserDetails, HttpServletResponse response, @CookieValue(value = "accessToken", required = false) String token) {
        log.info(token);
        String username = jwtTokenProvider.getUserName(token);
        String provider = (String) jwtTokenProvider.getClaims(token).get("provider");
        if(provider == null){
            jwtTokenProvider.deleteRefreshToken(username);
            jwtTokenProvider.addToBlacklist(token);
        }else{
            jwtTokenProvider.deleteRefreshToken(username, provider);
            jwtTokenProvider.addToBlacklist(token);
        }

        Cookie deleteAccessCookie = new Cookie("accessToken", null);
        deleteAccessCookie.setHttpOnly(true);
        deleteAccessCookie.setSecure(false);
        deleteAccessCookie.setPath("/");
        deleteAccessCookie.setMaxAge(0);

        response.addCookie(deleteAccessCookie);

        Cookie deleteRefreshCookie = new Cookie("refreshToken", null);
        deleteRefreshCookie.setHttpOnly(true);
        deleteRefreshCookie.setSecure(false);
        deleteRefreshCookie.setPath("/");
        deleteRefreshCookie.setMaxAge(0);

        response.addCookie(deleteRefreshCookie);

        Cookie memberEmailCookie = new Cookie("memberEmail", null);
        memberEmailCookie.setHttpOnly(true);
        memberEmailCookie.setSecure(false);
        memberEmailCookie.setPath("/");
        memberEmailCookie.setMaxAge(0);

        response.addCookie(memberEmailCookie);


        Cookie roleCookie = new Cookie("role", null);
        roleCookie.setHttpOnly(true);
        roleCookie.setSecure(false);
        roleCookie.setPath("/");
        roleCookie.setMaxAge(0);

        response.addCookie(roleCookie);

        Cookie deleteProviderCookie = new Cookie("provider", null);
        deleteProviderCookie.setHttpOnly(true);
        deleteProviderCookie.setSecure(false);
        deleteProviderCookie.setPath("/");
        deleteProviderCookie.setMaxAge(0);

        response.addCookie(deleteProviderCookie);
        if (customUserDetails != null) {
            Long memberId = customUserDetails.getId();
            memberService.deactivateMember(memberId);
        }
        return new RedirectView("/");
    }

//  마이페이지 - 나의 일기 목록 뷰
    @GetMapping("/diary-list")
    public String loadMyDiaryListPage() {
        log.info("마이페이지 - 일기 목록 화면 요청");
        return "mypage/my-diary/list";
    }

}
