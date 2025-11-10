package com.example.crewstation.service.gift;

import com.example.crewstation.dto.gift.GiftDTO;
import com.example.crewstation.repository.gift.GiftDAO;
import com.example.crewstation.service.s3.S3Service;
import com.example.crewstation.util.DateUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class GiftTransactionService {

    private final S3Service s3Service;
    private final RedisTemplate<String, Object> redisTemplate;
    private final GiftDAO giftDAO;
    private final GiftDTO giftDTO;

    @Transactional(rollbackFor = Exception.class)
    public List<GiftDTO> getMainGifts(int limit) {
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


}
