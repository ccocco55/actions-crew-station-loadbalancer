package com.example.crewstation.mapper.diary;

import com.example.crewstation.common.enumeration.Secret;
import com.example.crewstation.domain.diary.DiaryVO;
import com.example.crewstation.dto.diary.*;
import com.example.crewstation.util.Criteria;
import com.example.crewstation.util.ScrollCriteria;
import com.example.crewstation.util.Search;
import io.lettuce.core.Limit;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.security.core.parameters.P;
import retrofit2.http.PartMap;

import java.util.List;
import java.util.Optional;

@Mapper
public interface DiaryMapper {

    //    다이러리 목록 (메인)
    public List<DiaryDTO> selectDiaryList( @Param("memberId") Long memberId ,@Param("limit") int limit);

//   다이어리 이미지 개수
    public int countDiaryImg(@Param("postId") Long postId);

    //  해당 회원이 좋아요 한 다이어리 목록(마이페이지)
    public List<LikedDiaryDTO> findDiariesLikedByMemberId(
            @Param("memberId") Long memberId,
            @Param("criteria") ScrollCriteria criteria
    );

    // 특정 회원이 좋아요한 일기 수 조회
    public int countDiariesLikedByMemberId(@Param("memberId") Long memberId);

    // 좋아요 취소
    public void deleteLike(@Param("memberId") Long memberId,
                           @Param("diaryId") Long diaryId);

    // 추가: like_id 조회
    Long findLikeId(@Param("memberId") Long memberId, @Param("diaryId") Long diaryId);

    // 추가: 알림 삭제
    void deleteLikeAlarmByLikeId(@Param("likeId") Long likeId);

    // 내가 댓글 단 다이어리 조회
    public List<ReplyDiaryDTO> selectReplyDiariesByMemberId(@Param("memberId") Long memberId,
                                                     @Param("criteria") ScrollCriteria criteria);

    // 전체 개수 (hasMore 계산용)
    public int countReplyDiariesByMemberId(@Param("memberId") Long memberId);
//  다이어리 목록(다이어리 서비스쪽)
    public List<DiaryDTO> selectAllByKeyword(@Param("criteria") Criteria criteria, @Param("search") Search search);
// 다이리 목록 개수(다이어리 서비스쪽)
    public int selectCountAllByKeyword(@Param("search") Search search);
//    좋아요 증가/감소
    public void updateLikeCount(@Param("diff") int diff,@Param("postId")Long postId);

//   다이어리 목록 검색 개수
    public int searchDiaryCount(@Param("Search") Search search);

//  다이어리 저장
    public void insert(DiaryVO diaryVO);

//  다이어리 상세
    public Optional<DiaryDTO> selectByPostId(Long postId);
//  다이어리 공개/비공개 변경
    public void updateSecret(@Param("postId") Long postId,@Param("secret") Secret secret);
//   댓글 개수 증가 / 감소
    public void updateReplyCount(@Param("count") int count,@Param("postId") Long postId);
//    memberId로 다이어리 개수 조회
    public int selectCountDiaryAllByMemberId(Long memberId);
//    memberId로 다이어리  조회
    public List<DiaryDTO>  selectDiaryAllByMemberId(Long memberId);

//  나의 다이어리 목록 조회
    public List<MyDiaryDTO> selectMyDiaryListByCriteria(Long memberId, ScrollCriteria criteria);

    // 나의 다이어리 총 개수 조회
    public int countMyDiariesByMemberId(Long memberId);

//  좋아요 개수 게시
    public String selectLikeCountByPostId(Long postId);
}
