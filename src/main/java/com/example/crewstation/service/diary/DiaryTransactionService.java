package com.example.crewstation.service.diary;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.common.exception.DiaryNotFoundException;
import com.example.crewstation.dto.accompany.AccompanyDTO;
import com.example.crewstation.dto.accompany.AccompanyPathDTO;
import com.example.crewstation.dto.country.CountryDTO;
import com.example.crewstation.dto.diary.DiaryDTO;
import com.example.crewstation.dto.diary.DiaryDetailDTO;
import com.example.crewstation.dto.post.file.tag.PostFileTagDTO;
import com.example.crewstation.dto.post.section.SectionDTO;
import com.example.crewstation.repository.diary.DiaryDAO;
import com.example.crewstation.repository.diary.country.DiaryCountryDAO;
import com.example.crewstation.repository.like.LikeDAO;
import com.example.crewstation.repository.post.PostDAO;
import com.example.crewstation.repository.post.file.tag.PostFileTagDAO;
import com.example.crewstation.repository.section.SectionDAO;
import com.example.crewstation.service.s3.S3Service;
import com.example.crewstation.util.DateUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class DiaryTransactionService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final S3Service s3Service;
    private final DiaryDTO diaryDTO;
    private final SectionDAO sectionDAO;
    private final RedisTemplate<String, DiaryDetailDTO> diaryDetailRedisTemplate;
    private final DiaryDAO diaryDAO;
    private final PostDAO postDAO;
    private final DiaryCountryDAO diaryCountryDAO;
    private final LikeDAO likeDAO;
    private final PostFileTagDAO postFileTagDAO;

    @Transactional(rollbackFor = Exception.class)
    public List<DiaryDTO> selectDiaryList (int limit, Long memberId) {
        List<DiaryDTO> diaries = diaryDAO.selectDiaryList(memberId ,limit);
        diaries.forEach(diary -> {
            String filePath = diary.getDiaryFilePath();
            String presignedUrl = s3Service.getPreSignedUrl(filePath, Duration.ofMinutes(5));
            diary.setFileCount(sectionDAO.findSectionFileCount(diary.getPostId()));
            if(diary.getMemberFilePath() != null){
                diary.setMemberFilePath(s3Service.getPreSignedUrl(diary.getMemberFilePath(), Duration.ofMinutes(5)));
            }
            log.info("Diary ID={}, 원본 DiaryfilePath={}, 발급된 presignedUrl={}",
                    diary, filePath, presignedUrl);
            diary.setDiaryFilePath(presignedUrl);
        });
//        redisTemplate.opsForValue().set("diaries", diaries, Duration.ofMinutes(5));
        return diaries;
    }

    @Transactional(rollbackFor = Exception.class)
    public DiaryDetailDTO getDiary (Long postId,CustomUserDetails customUserDetails) {
        DiaryDetailDTO diaryDetailDTO = new DiaryDetailDTO();
        postDAO.updateReadCount(postId);
        List<CountryDTO> countries = diaryCountryDAO.findCountryByPostId(postId);
        Optional<DiaryDTO> byPostId = diaryDAO.findByPostId(postId);


        byPostId.ifPresent(diaryDTO -> {
            diaryDTO.setDiaryLikeCount(diaryDAO.findLikeCountByPostId(postId));
            if (customUserDetails != null) {
                diaryDTO.setUserId(customUserDetails.getId());
                Long likeId = likeDAO.isLikeByPostIdAndMemberId(diaryDTO);
                diaryDTO.setUserId(Objects.equals(diaryDTO.getUserId(), diaryDTO.getMemberId()) ? customUserDetails.getId() : null);
                diaryDTO.setLikeId(likeId);
            }
            if(diaryDTO.getMemberFilePath() != null){
                diaryDTO.setMemberFilePath(s3Service.getPreSignedUrl(diaryDTO.getMemberFilePath(), Duration.ofMinutes(5)));
            }
            diaryDTO.setRelativeDate(DateUtils.toRelativeTime(diaryDTO.getCreatedDatetime()));

            log.info("유저 아이디{}",diaryDTO.getUserId());
        });
        diaryDetailDTO.setCountries(countries);


        diaryDetailDTO.setDiary(byPostId.orElseThrow(DiaryNotFoundException::new));
        diaryDetailRedisTemplate.opsForValue().set("diary::diary_" + postId, diaryDetailDTO);

        List<SectionDTO> sections = sectionDAO.findSectionsByPostId(postId);
        sections.forEach(section -> {
            log.info("{}", section.getFileId());
            List<PostFileTagDTO> tags = postFileTagDAO.findByFileId(section.getFileId());
            log.info("{}:::::::::::::::::::::::::", tags);
            section.setTags(tags);
            if (section.getFilePath() != null) {
                section.setFilePath(s3Service.getPreSignedUrl(section.getFilePath(), Duration.ofMinutes(5)));
            }
            tags.forEach((tag) -> {
                log.info("tag가 존재하나 :{}", tag);
                if (tag.getFilePath() != null) {
                    tag.setFilePath(s3Service.getPreSignedUrl(tag.getFilePath(), Duration.ofMinutes(5)));
                }
            });

        });
        diaryDetailDTO.setSections(sections);
        return diaryDetailDTO;
    }
}
