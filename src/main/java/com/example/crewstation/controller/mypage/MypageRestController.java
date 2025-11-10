package com.example.crewstation.controller.mypage;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.common.enumeration.PaymentPhase;
import com.example.crewstation.dto.diary.MyDiaryCriteriaDTO;
import com.example.crewstation.dto.diary.MyDiaryDTO;
import com.example.crewstation.dto.member.MemberProfileDTO;
import com.example.crewstation.dto.member.ModifyDTO;
import com.example.crewstation.dto.member.MyPurchaseDetailDTO;
import com.example.crewstation.dto.member.MySaleDetailDTO;
import com.example.crewstation.service.diary.DiaryService;
import com.example.crewstation.service.member.MemberService;
import com.example.crewstation.service.purchase.PurchaseService;
import com.example.crewstation.util.ScrollCriteria;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api/mypage/**")
public class MypageRestController {

    private final MemberService memberService;
    private final PurchaseService purchaseService;
    private final DiaryService diaryService;


    // 구매 상세 조회
    @GetMapping("/purchase-detail/{postId}")
    public ResponseEntity<MyPurchaseDetailDTO> getPurchaseDetail(
            @AuthenticationPrincipal CustomUserDetails customUserDetails,
            @PathVariable Long postId) {

        Long memberId = customUserDetails.getId();
        log.info("GET /purchase-detail called by memberId={}, postId={}", memberId, postId);

        MyPurchaseDetailDTO orderDetail = purchaseService.getMemberOrderDetails(memberId, postId);

        if (orderDetail == null) {
            log.warn("Order not found for memberId={}, postId={}", memberId, postId);
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(orderDetail);
    }

    // 결제 상태 업데이트
    @PutMapping("/purchase-detail/{paymentStatusId}/status")
    public ResponseEntity<Void> updatePaymentStatus(
            @AuthenticationPrincipal CustomUserDetails customUserDetails,
            @PathVariable Long paymentStatusId,
            @RequestParam PaymentPhase paymentPhase) {

        Long memberId = customUserDetails.getId();
        log.info("PUT /purchase-detail/{}/status called by memberId={}, phase={}", paymentStatusId, memberId, paymentPhase);

        MyPurchaseDetailDTO order = purchaseService.getMemberOrderDetails(memberId, paymentStatusId);
        if (order == null) {
            log.warn("Order not found for memberId={}, paymentStatusId={}", memberId, paymentStatusId);
            return ResponseEntity.notFound().build();
        }

        purchaseService.updatePaymentStatus(paymentStatusId, paymentPhase);
        log.info("Payment status updated for paymentStatusId={}, newStatus={}", paymentStatusId, paymentPhase);
        return ResponseEntity.ok().build();
    }


    //   판매 상태 업데이트
    @PutMapping("/status/{paymentStatusId}")
    public ResponseEntity<Void> updateSaleStatus(
            @PathVariable Long paymentStatusId,
            @RequestParam String paymentPhase,
            @AuthenticationPrincipal CustomUserDetails customUserDetails) {

        Long memberId = customUserDetails.getId();
        log.info("PUT /api/mypage/status/{} by memberId={} with phase={}",
                paymentStatusId, memberId, paymentPhase);

        // 서비스 호출
        memberService.updateSaleStatus(memberId, paymentStatusId, PaymentPhase.valueOf(paymentPhase));

        return ResponseEntity.ok().build();
    }

    //  마이페이지 - 판매 상세 조회
    @GetMapping("/sale-detail/{paymentStatusId}")
    public ResponseEntity<MySaleDetailDTO> getMySaleDetail(
            @AuthenticationPrincipal CustomUserDetails customUserDetails,
            @PathVariable("paymentStatusId") Long paymentStatusId) {

        Long sellerId = customUserDetails.getId();
        log.info("판매 상세 요청 - sellerId={}, paymentStatusId={}", sellerId, paymentStatusId);

        MySaleDetailDTO detail = memberService.getSellerOrderDetails(sellerId, paymentStatusId);

        if (detail == null) {
            log.warn("판매 상세 정보 없음 - sellerId={}, paymentStatusId={}", sellerId, paymentStatusId);
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(detail);
    }

    @GetMapping("/profile")
    public MemberProfileDTO getMyPageProfile(@AuthenticationPrincipal CustomUserDetails customUserDetails) {
        return memberService.getMyPageProfile(customUserDetails);
    }

    //  마이페이지 - 일기 목록 조회
    @GetMapping("/diary/list")
    public ResponseEntity<MyDiaryCriteriaDTO> getMyDiaries(
            @AuthenticationPrincipal CustomUserDetails customUserDetails,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "8") int size) {

    log.info("[나의 다이어리 조회 요청] memberId={}, page={}, size={}",
            customUserDetails.getId(), page, size);

    ScrollCriteria criteria = new ScrollCriteria(page, size);

    MyDiaryCriteriaDTO dto = diaryService.getMyDiaryListByCriteria(customUserDetails,criteria);

    return ResponseEntity.ok(dto);

    }

    //  나의 다이어리 총 개수
    @GetMapping("/diary/count")
    public ResponseEntity<Integer> getMyDiaryCount(
            @AuthenticationPrincipal CustomUserDetails customUserDetails) {

        int count = diaryService.getCountMyDiariesByMemberId(customUserDetails);
        return ResponseEntity.ok(count);
    }

}