package com.example.crewstation.controller.admin;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.domain.notice.NoticeDetailVO;
import com.example.crewstation.dto.ask.AskDTO;
import com.example.crewstation.dto.banner.BannerDTO;
import com.example.crewstation.dto.member.MemberAdminStatics;
import com.example.crewstation.dto.member.MemberCriteriaDTO;
import com.example.crewstation.dto.member.MemberDTO;
import com.example.crewstation.dto.notice.NoticeCriteriaDTO;
import com.example.crewstation.dto.notice.NoticeWriteRequest;
import com.example.crewstation.dto.payment.status.PaymentCriteriaDTO;
import com.example.crewstation.dto.report.post.ReportPostDTO;
import com.example.crewstation.repository.payment.PaymentDAO;
import com.example.crewstation.repository.payment.status.PaymentStatusDAO;
import com.example.crewstation.service.accompany.AccompanyService;
import com.example.crewstation.service.ask.adminAsk.AdminAskService;
import com.example.crewstation.service.banner.BannerService;
import com.example.crewstation.service.banner.BannerTransactionService;
import com.example.crewstation.service.member.MemberService;
import com.example.crewstation.service.notice.NoticeDetailService;
import com.example.crewstation.service.notice.NoticeService;
import com.example.crewstation.service.payment.PaymentService;
import com.example.crewstation.service.gift.GiftService;
import com.example.crewstation.service.report.ReportService;
import com.example.crewstation.util.Search;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Slf4j
public class AdminRestController implements AdminRestControllerDocs{

    private final MemberService memberService;
    private final NoticeService noticeService;
    private final NoticeDetailService noticeDetailService;
    private final ReportService reportService;
    private final GiftService giftService;
    private final PaymentService paymentService;
    private final PaymentDAO paymentDAO;
    private final PaymentStatusDAO paymentStatusDAO;
    private final AdminAskService adminAskService;
    private static final Map<String, String> PHASE_MAP = Map.of(
            "결제 진행중", "PROGRESS",
            "결제완료", "SUCCESS",
            "결제취소", "CANCEL"
    );
    private final BannerTransactionService bannerTransactionService;
    private final BannerService bannerService;
    private final AccompanyService accompanyService;

    //    관리자 회원 목록
    @PostMapping("/members")
    public ResponseEntity<MemberCriteriaDTO> getMembers(@RequestBody Search search) {
        return ResponseEntity.ok(memberService.getMembers(search));
    }

    //    관리자 회원 상세
    @GetMapping("/members/{memberId}")
    public ResponseEntity<MemberDTO> getMemberDetails(@PathVariable Long memberId) {
        return ResponseEntity.ok(memberService.getMemberDetail(memberId));
    }

    //    관리자 메인 회원 통계
    @GetMapping({"", "/"})
    public ResponseEntity<MemberAdminStatics> getStatics() {
        MemberAdminStatics statics = memberService.getStatics();
        return ResponseEntity.ok(statics);

    }

    //  공지사항 목록
    @GetMapping("/notices")
    public ResponseEntity<NoticeCriteriaDTO> getAdminNotices(@RequestParam(defaultValue = "1") int page) {
        int safePage = Math.max(1, page);
        return ResponseEntity.ok(noticeService.getAdminNotices(safePage));
    }

    //    공지사항 작성
    @PostMapping("/notices")
    public ResponseEntity<?> createNotice(@AuthenticationPrincipal CustomUserDetails admin,
                                          @RequestBody NoticeWriteRequest req) {
        Long memberId = admin.getId();
        Long id = noticeService.insertNotice(memberId, req.getTitle(), req.getContent());
        if (id == null) {
            return ResponseEntity.status(HttpStatus.CREATED).body(new HashMap<>());
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", id));
    }


    //    공지사항 상세
    @GetMapping("/notices/{id}")
    public ResponseEntity<NoticeDetailVO> noticeDetail(@PathVariable Long id) {
        NoticeDetailVO notice = noticeDetailService.getDetail(id);
        return ResponseEntity.ok(notice);
    }

    //    다이어리 신고 목록
    @GetMapping("/diaries")
    public ResponseEntity<List<ReportPostDTO>> getReportDiaryList(@RequestParam(defaultValue = "1") int page) {
        int safePage = Math.max(1, page);
        List<ReportPostDTO> reports = reportService.getReportDiaries(safePage);
        return ResponseEntity.ok(reports);
    }

    //    다이어리 신고 처리
    @PostMapping("/diary/{reportId}/process")
    public ResponseEntity<ReportPostDTO> processDiaryReport(@PathVariable Long reportId, @RequestParam(required = false) Long postId, @RequestParam(defaultValue = "false") boolean hidePost) {

        log.info("다이어리 신고 reportId={}, postId={}, hidePost={}", reportId, postId, hidePost);

        if (hidePost && postId != null) {
            reportService.hidePost(postId);
        }

        reportService.resolveReport(reportId);

        return ResponseEntity.ok().build();
    }

    //    기프트 신고 목록
    @GetMapping("/gifts")
    public ResponseEntity<List<ReportPostDTO>> getReportGiftList(@RequestParam(defaultValue = "1") int page) {
        int safePage = Math.max(1, page);
        List<ReportPostDTO> reports = giftService.getReportGifts(safePage);
        return ResponseEntity.ok(reports);
    }

    //    기프트 신고 처리
    @PostMapping("/gift/{reportId}/process")
    public ResponseEntity<ReportPostDTO> processGiftReport(@PathVariable Long reportId, @RequestParam(required = false) Long postId, @RequestParam(defaultValue = "false") boolean hidePost) {

        log.info("기프트 신고 reportId={}, postId={}, hidePost={}", reportId, postId, hidePost);

        if (hidePost && postId != null) {
            giftService.hidePost(postId);
        }

        giftService.resolveReport(reportId);

        return ResponseEntity.ok().build();
    }
    
    //    결제 목록
    @GetMapping("/payment")
    public ResponseEntity<?> getPayment(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(required = false) String categories,
            @RequestParam(required = false) String keyword) {

        Search search = new Search();
        search.setPage(Math.max(1, page));
        if (keyword != null) search.setKeyword(keyword);

        if (categories != null && !categories.isBlank()) {
            List<String> cats = Arrays.stream(categories.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(s -> PHASE_MAP.getOrDefault(s, s.toUpperCase()))
                    .collect(Collectors.toList());

            if (cats.size() == 3) {
                search.setCategories(null);
            } else {
                search.setCategories(cats);
            }
        }
        int size = 16;
        List<PaymentCriteriaDTO> list = paymentService.selectPayment(search, size);
        return ResponseEntity.ok(list);
    }


    //  결제 목록 상세 보기
    @GetMapping("/payment/{id}")
    public ResponseEntity<PaymentCriteriaDTO> getPaymentDetail(@PathVariable Long id) {
        return ResponseEntity.ok(paymentService.getPaymentDetail(id));
    }

//    걀제 승인/취소 금액
    @GetMapping("/payment/summary")
    public ResponseEntity<Map<String, Object>> getPaymentSummary(
            @RequestParam(required = false) String categories,
            @RequestParam(required = false) String keyword) {

        Search search = new Search();
        if (keyword != null && !keyword.isBlank()) search.setKeyword(keyword);

        if (categories != null && !categories.isBlank()) {
            List<String> cats = Arrays.stream(categories.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(String::toUpperCase)
                    .collect(Collectors.toList());
            if (cats.size() >= 3) search.setCategories(null);
            else search.setCategories(cats);
        }

        return ResponseEntity.ok(paymentService.getPaymentSummary(search));
    }

    @GetMapping("/inquiries")
    public ResponseEntity<List<AskDTO>> getInquiryList(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String category) {

        Search search = new Search();
        if (keyword != null && !keyword.isBlank()) search.setKeyword(keyword);
        if (category != null && !category.isBlank()) search.setCategory(category);

        List<AskDTO> list = adminAskService.getInquiryList(search);
        return ResponseEntity.ok(list);
    }

    // 문의 상세 조회
    @GetMapping("/inquiries/{id}")
    public ResponseEntity<AskDTO> getInquiryDetail(@PathVariable Long id) {
        return ResponseEntity.ok(adminAskService.getInquiryDetail(id));
    }

    // 문의 답변 등록
    @PostMapping("/inquiries/{id}/reply")
    public ResponseEntity<Void> registerReply(
            @PathVariable Long id,
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal CustomUserDetails admin
    ) {
        String replyContent = body.getOrDefault("replyContent", "").trim();
        if (replyContent.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        AskDTO dto = new AskDTO();
        dto.setId(id);
        dto.setMemberId(admin.getId());
        dto.setReplyContent(replyContent);

        adminAskService.registerReply(dto);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/banner")
    public ResponseEntity<List<BannerDTO>> getBanners(@RequestParam(defaultValue = "5") int limit) {
        log.info("getBanners ={}", limit);
        return ResponseEntity.ok(bannerService.getBanners(limit));
    }

    @PostMapping("/banner")
    public ResponseEntity<?> insertBanner(@AuthenticationPrincipal CustomUserDetails admin,
                                             @ModelAttribute BannerDTO bannerDTO,
                                             @RequestParam(value = "files", required = false) List<MultipartFile> files) {
        if (bannerDTO.getBannerOrder() == 0 && admin != null) {
            bannerDTO.setBannerOrder(Math.toIntExact(admin.getId()));
        }
        bannerService.insertBannerFile(bannerDTO, files);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/banner/{bannerId}")
    public ResponseEntity<Void> updateBanner(@PathVariable Long bannerId,
                                             @ModelAttribute BannerDTO bannerDTO,
                                             @RequestParam(value = "deleteFiles", required = false) Long[] deleteFiles,
                                             @RequestParam(value = "files", required = false) List<MultipartFile> multipartFiles) {
        bannerDTO.setBannerId(bannerId);
        bannerService.updateBanner(bannerDTO, deleteFiles, multipartFiles);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/banner/{bannerId}")
    public ResponseEntity<Void> deleteBanner(@PathVariable Long bannerId) {
        bannerService.deleteBanner(bannerId);
        return ResponseEntity.ok().build();
    }

//    관리자 동행 신고 목록
    @GetMapping("/accompanies")
    public ResponseEntity<List<ReportPostDTO>> getAccompanies(Search search) {
        List<ReportPostDTO> reports = reportService.getReportAccompanies(search);
        return ResponseEntity.ok(reports);
    }

//    관리자 동행신고 처리
    @PostMapping("/accompanies/{reportId}/process")
    public ResponseEntity<List<ReportPostDTO>> getAccompanies(@PathVariable Long reportId,
                                                              @RequestParam(required = false) Long postId,
                                                              @RequestParam(defaultValue = "false") boolean hidePost) {
        log.info("process report: reportId={}, postId={}, hidePost={}", reportId, postId, hidePost);
        if (hidePost && postId != null) {
            reportService.hidePost(postId);
        }
        reportService.resolveReport(reportId);

        return ResponseEntity.ok().build();
    }




}
