package com.example.crewstation.controller.purchase;

import com.example.crewstation.auth.JwtTokenProvider;
import com.example.crewstation.common.exception.PostNotFoundException;
import com.example.crewstation.dto.member.MemberDTO;
import com.example.crewstation.dto.purchase.PurchaseCriteriaDTO;
import com.example.crewstation.dto.purchase.PurchaseDTO;
import com.example.crewstation.dto.report.ReportDTO;
import com.example.crewstation.service.purchase.PurchaseService;
import com.example.crewstation.util.Search;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api/gifts/**")
public class PurchaseRestController {
    private final PurchaseService purchaseService;

    @GetMapping
    public ResponseEntity<PurchaseCriteriaDTO> getPurchases(Search search) {
        PurchaseCriteriaDTO purchases = purchaseService.getPurchases(search);
        return ResponseEntity.ok().body(purchases);
    }

}
