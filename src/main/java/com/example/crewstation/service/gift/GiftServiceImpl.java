package com.example.crewstation.service.gift;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.common.enumeration.ProcessStatus;
import com.example.crewstation.common.enumeration.Status;
import com.example.crewstation.dto.gift.GiftCriteriaDTO;
import com.example.crewstation.dto.gift.GiftDTO;
import com.example.crewstation.dto.report.post.ReportPostDTO;
import com.example.crewstation.repository.gift.GiftDAO;
import com.example.crewstation.repository.report.ReportDAO;
import com.example.crewstation.service.s3.S3Service;
import com.example.crewstation.util.Criteria;
import com.example.crewstation.util.DateUtils;
import com.example.crewstation.util.ScrollCriteria;
import com.example.crewstation.util.Search;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.List;
import java.util.Map;


@Service
@RequiredArgsConstructor
@Slf4j
public class GiftServiceImpl implements GiftService {

    private final GiftDAO giftDAO;
    private final S3Service s3Service;
    private static final Map<String, String> ORDER_TYPE_MAP = Map.of(
            "좋아요순", "vpp.purchase_product_count desc",
            "최신순",   "vpp.created_datetime desc"
    );
    private static final Map<String, String> CATEGORY_MAP = Map.of(
            "crew", "not null",
            "individual", "null"
    );
    private final ReportDAO reportDAO;


    @Override
    @Transactional(rollbackFor = Exception.class)
    public List<GiftDTO> getGift(int limit) {
        List<GiftDTO> gifts = giftDAO.getMainGifts(limit);
        gifts.forEach(gift -> {
            String filePath = gift.getFilePath();
            String presignedUrl = s3Service.getPreSignedUrl(filePath, Duration.ofMinutes(5));
            if(gift.getMemberFilePath() != null){
                gift.setMemberFilePath(s3Service.getPreSignedUrl(gift.getMemberFilePath(), Duration.ofMinutes(5)));
            }
            gift.setRelativeDate(DateUtils.toRelativeTime(gift.getCreatedDatetime()));
            gift.setLimitDateTime(DateUtils.calcLimitDateTime(gift.getCreatedDatetime(),gift.getPurchaseLimitTime()));
            log.info("Gift ID={}, 원본 filePath={}, 발급된 presignedUrl={}",
                    gift, filePath, presignedUrl);

            gift.setFilePath(s3Service.getPreSignedUrl(gift.getFilePath(), Duration.ofMinutes(5)));

        });
//        redisTemplate.opsForValue().set("gifts", gifts, Duration.ofMinutes(5));
        return gifts;
    }

    @Override
    public GiftCriteriaDTO getGifts(Search search, CustomUserDetails customUserDetails) {
        GiftCriteriaDTO dto = new GiftCriteriaDTO();
        Search newSearch = new Search();
        int page = search.getPage();
        dto.setSearch(search);

        String category = search.getCategory();
        String orderType = search.getOrderType();

        newSearch.setKeyword(search.getKeyword());
        String orderBy   = ORDER_TYPE_MAP.getOrDefault(orderType == null ? "" : orderType,
                "vpp.created_datetime desc");
        String categoryDb = CATEGORY_MAP.getOrDefault(category == null ? "" : category, "");

        newSearch.setKeyword(search.getKeyword());
        newSearch.setOrderType(orderBy);
        newSearch.setCategory(categoryDb);

        int totalCount = giftDAO.countGifts(newSearch);
        Criteria criteria = new Criteria(page, totalCount, 4, 4);

        List<GiftDTO> gifts = giftDAO.findGifts(criteria, newSearch);

        gifts.forEach(gift -> {
            if (gift.getFilePath() != null) {
                gift.setFilePath(s3Service.getPreSignedUrl(gift.getFilePath(), Duration.ofMinutes(5)));
            }
            if (gift.getCreatedDatetime() != null) {
                gift.setRelativeDate(DateUtils.toRelativeTime(gift.getCreatedDatetime()));
            }
            if (gift.getMemberFilePath() != null) {
                gift.setMemberFilePath(
                        s3Service.getPreSignedUrl(gift.getMemberFilePath(), Duration.ofMinutes(5))
                );
            }
            if (gift.getCreatedDatetime() != null && gift.getPurchaseLimitTime() != null) {
                gift.setLimitDateTime(
                        DateUtils.calcLimitDateTime(gift.getCreatedDatetime(), gift.getPurchaseLimitTime())
                );
            }

        });

        criteria.setHasMore(gifts.size() > criteria.getRowCount());
        if (criteria.isHasMore()) {
            gifts.remove(gifts.size() - 1);
        }

        dto.setGiftDTOs(gifts);
        dto.setCriteria(criteria);
        dto.setTotalCount(totalCount);

        return dto;
    }

    @Override
    public List<ReportPostDTO> getReportGifts(int page) {
        ScrollCriteria scrollCriteria = new ScrollCriteria(page, 10);
//        log.info("스크롤 페이지 번호 = {}", scrollCriteria.getPage());
        return reportDAO.findAllReportGifts(scrollCriteria);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void hidePost(Long postId) {
        log.info("게시글 숨김 postId={}", postId);
        reportDAO.updatePostStatus(postId, Status.INACTIVE.getValue());
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void resolveReport(Long reportId) {
        log.info("신고 처리 상태 변경 reportId={}", reportId);
        reportDAO.updateReportProcessStatus(reportId, ProcessStatus.RESOLVED.getValue());
    }

}
