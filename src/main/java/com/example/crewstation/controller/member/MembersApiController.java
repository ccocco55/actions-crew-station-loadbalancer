package com.example.crewstation.controller.member;

import com.example.crewstation.aop.aspect.annotation.LogReturnStatus;
import com.example.crewstation.aop.aspect.annotation.LogStatus;
import com.example.crewstation.dto.member.MemberDTO;
import com.example.crewstation.dto.member.MemberProfileDTO;
import com.example.crewstation.service.mail.MailService;
import com.example.crewstation.service.member.MemberService;
import com.example.crewstation.service.sms.JoinSmsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/member/**")
@RequiredArgsConstructor
@Slf4j
public class MembersApiController implements MembersApiControllerDocs {
    private final MemberService memberService;
    private final MailService mailService;
    private final JoinSmsService joinSmsService;

//    이메일 중복 검사
    @PostMapping("email-check")
    @LogReturnStatus
    public ResponseEntity<Boolean> checkEmail(@RequestParam String email) {
        boolean check = memberService.checkEmail(email);

        return ResponseEntity.ok(check);

    }


    @GetMapping("/{memberId}")
    public ResponseEntity<MemberDTO> getMemberProfile(@PathVariable Long memberId) {
        return memberService.getMemberProfile(memberId)
                .map(ResponseEntity::ok)      // 값이 있으면 200ok
                .orElse(ResponseEntity.notFound().build()); // 없으면 404
    }

//    이메일로 인증 코드 전송
    @PostMapping("/send-email")
    @LogReturnStatus
    public ResponseEntity<Map<String, String>> sendEmail(@RequestParam("email") String email) {
        try {
            String code = mailService.sendMail(email);
            return ResponseEntity.ok(Map.of("code", code));

        } catch (jakarta.mail.MessagingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "메일 전송 실패"));

        }
    }

//    핸드폰 인증 메세지 발송
    @PostMapping("/phone-check")
    @LogReturnStatus
    public ResponseEntity<Map<String, String>> checkPhone(@RequestParam String phone) {
        String code = joinSmsService.send(phone);
        log.info("code: {}", code);
        return ResponseEntity.ok(Map.of("code", code));
    }


    
//  별점 등록 시 케미지수 + 상태 업데이트
    @PostMapping("/rating")
    public ResponseEntity<?> giveRating(@RequestBody Map<String, Object> body) {
        Long sellerId = Long.valueOf(body.get("sellerId").toString());
        Long paymentStatusId = Long.valueOf(body.get("paymentStatusId").toString());
        int rating = Integer.parseInt(body.get("rating").toString());

        memberService.submitReview(sellerId, paymentStatusId, rating);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "별점이 반영되고 주문 상태가 reviewed로 변경되었습니다."
        ));
    }
    @GetMapping("profile/{memberId}")
    public MemberDTO getProfileMember(@PathVariable Long memberId) {
        return memberService.getProfileMember(memberId);
    }

}
