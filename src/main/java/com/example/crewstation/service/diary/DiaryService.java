package com.example.crewstation.service.diary;


import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.domain.diary.DiaryVO;
import com.example.crewstation.domain.diary.country.DiaryCountryVO;
import com.example.crewstation.domain.diary.diary.path.DiaryDiaryPathVO;
import com.example.crewstation.domain.file.section.FilePostSectionVO;
import com.example.crewstation.domain.post.PostVO;
import com.example.crewstation.domain.post.file.tag.PostFileTagVO;
import com.example.crewstation.domain.post.section.PostSectionVO;
import com.example.crewstation.dto.diary.*;
import com.example.crewstation.dto.file.section.FilePostSectionDTO;
import com.example.crewstation.dto.file.tag.ImageDTO;
import com.example.crewstation.dto.file.tag.PostDiaryDetailTagDTO;
import com.example.crewstation.dto.post.PostDTO;
import com.example.crewstation.dto.post.file.tag.PostFileTagDTO;
import com.example.crewstation.dto.post.section.PostSectionDTO;
import com.example.crewstation.dto.purchase.PurchaseDTO;
import com.example.crewstation.repository.diary.diary.path.DiaryDiaryPathDAO;
import com.example.crewstation.util.ScrollCriteria;
import com.example.crewstation.util.Search;
import org.apache.ibatis.annotations.Param;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public interface DiaryService {

    // 특정 회원이 좋아요한 일기 목록 조회
    public LikedDiaryCriteriaDTO getDiariesLikedByMemberId(CustomUserDetails customUserDetails, ScrollCriteria criteria);

    // 특정 회원이 좋아요한 일기 수 조회
    public int getCountDiariesLikedByMemberId(CustomUserDetails customUserDetails);

    //  좋아요 취소
    public void cancelLike (CustomUserDetails customUserDetails, Long diaryId);

    //    다이어리 목록 조회
    public List<DiaryDTO> selectDiaryList(Long memberId ,int limit);
    //    내가 댓글 쓴 일기 조회
    public ReplyDiaryCriteriaDTO getReplyDiariesByMemberId(CustomUserDetails customUserDetails, ScrollCriteria criteria);

    //  내가 답글 단 일기 개수 조회
    public int getCountReplyDiariesByMemberId (CustomUserDetails customUserDetails);


//    다이어리 목록들 가져오기(다이어리 서비스 쪽)
    public DiaryCriteriaDTO getDiaries(Search search, CustomUserDetails customUserDetails);

//    다이어리 이미지 개수
    public DiaryCriteriaDTO countDiaryImg(Search search, CustomUserDetails customUserDetails);

//    다이어리 작성
    public void write(PostDiaryDetailTagDTO request);
//  다이어리 업데이트
    public void update(PostDiaryDetailTagDTO request);
    // 다이어리 상세 내용 가져오기
    public DiaryDetailDTO getDiary(Long postId,CustomUserDetails customUserDetails);

//    다이어리 공개 비공개 변경
    public String changeSecret(Long diaryId, boolean check);
//    memberId로 다이어리  조회
    public List<DiaryDTO> findDiaryById(Long diaryId);

    // 나의 다이어리 목록 조회
    public MyDiaryCriteriaDTO getMyDiaryListByCriteria(CustomUserDetails customUserDetails, ScrollCriteria criteria);

    // 나의 다이어리 총 개수
    public int getCountMyDiariesByMemberId(CustomUserDetails customUserDetails);


    public void deleteDiary(Long postId);
    default DiaryVO toDiaryVO(PostDTO postDTO) {
        return DiaryVO.builder()
                .diarySecret(postDTO.getSecret())
                .postId(postDTO.getPostId())
                .build();
    }
    default List<DiaryCountryVO> toDiaryCountryVO(PostDiaryDetailTagDTO postDiaryDetailTagDTO) {
        return postDiaryDetailTagDTO.getCountryIds().stream()
                .map(countryId -> DiaryCountryVO.builder()
                        .countryId(countryId)
                        .postId(postDiaryDetailTagDTO.getPostId())
                        .build())
                .collect(Collectors.toList());
    }
    default DiaryDiaryPathVO toDiaryDiaryPathVO(PostDiaryDetailTagDTO postDiaryDetailTagDTO) {
        return DiaryDiaryPathVO.builder()
                .diaryPathId(postDiaryDetailTagDTO.getDiaryPathId())
                .postId(postDiaryDetailTagDTO.getPostId())
                .build();
    }
    default PostFileTagVO toPostFileTagVO(PostFileTagDTO postFileTagDTO) {
        return PostFileTagVO.builder()
                .tagTop(postFileTagDTO.getTagTop())
                .tagLeft(postFileTagDTO.getTagLeft())
                .postSectionFileId(postFileTagDTO.getPostSectionFileId())
                .memberId(postFileTagDTO.getMemberId())
                .createdDatetime(postFileTagDTO.getCreatedDatetime())
                .updatedDatetime(postFileTagDTO.getUpdatedDatetime())
                .build();
    }

    default FilePostSectionVO toSectionFileVO(FilePostSectionDTO sectionFileDTO) {
        return FilePostSectionVO.builder()
                .fileId(sectionFileDTO.getFileId())
                .postSectionId(sectionFileDTO.getPostSectionId())
                .imageType(sectionFileDTO.getImageType())
                .createdDatetime(sectionFileDTO.getCreateDatetime())
                .updatedDatetime(sectionFileDTO.getUpdateDatetime())
                .build();
    }

    default PostSectionVO toPostSectionVO(ImageDTO imageDTO) {
        return PostSectionVO.builder()
                .id(imageDTO.getPostSectionId())
                .postContent(imageDTO.getPostContent())
                .build();
    }

    default PostVO toPostVO(PostDiaryDetailTagDTO postDiaryDetailTagDTO) {
        return PostVO.builder()
                .id(postDiaryDetailTagDTO.getPostId())
                .postTitle(postDiaryDetailTagDTO.getPostTitle())
                .build();
    }
}


