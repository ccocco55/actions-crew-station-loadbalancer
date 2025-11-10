package com.example.crewstation.repository.diary;

import com.example.crewstation.common.enumeration.Secret;
import com.example.crewstation.domain.diary.DiaryVO;
import com.example.crewstation.dto.diary.*;
import com.example.crewstation.mapper.diary.DiaryMapper;
import com.example.crewstation.util.Criteria;
import com.example.crewstation.util.ScrollCriteria;
import com.example.crewstation.util.Search;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@Slf4j
@RequiredArgsConstructor
public class DiaryDAO {

    private final DiaryMapper diaryMapper;

    //    다이어리 목록 조회
    public List<DiaryDTO> selectDiaryList(Long memberId ,int limit)
    {
        return diaryMapper.selectDiaryList(memberId ,limit);
    }

    // 특정 회원이 좋아요한 일기 목록 조회
    public List<LikedDiaryDTO> findDiariesLikedByMemberId(Long memberId, ScrollCriteria criteria) {
        return diaryMapper.findDiariesLikedByMemberId(memberId, criteria);
    }

    // 특정 회원이 좋아요한 일기 수 조회
    public int countDiariesLikedByMemberId(Long memberId) {
        return diaryMapper.countDiariesLikedByMemberId(memberId);
    }

    //    좋아요 취소
    public void deleteLike(Long memberId, Long diaryId) {
        diaryMapper.deleteLike(memberId, diaryId);
    }

    //  좋아요 한 아이디 찾기
    public Long findLikeId(Long memberId, Long diaryId) {
        return diaryMapper.findLikeId(memberId, diaryId);
    }
    //  좋아요 알람 삭제
    public void deleteLikeAlarmByLikeId(Long likeId) {
        diaryMapper.deleteLikeAlarmByLikeId(likeId);
    }

    // 내가 댓글 단 일기 조회
    public List<ReplyDiaryDTO> findReplyDiariesByMemberId(Long memberId, ScrollCriteria criteria) {
        return diaryMapper.selectReplyDiariesByMemberId(memberId, criteria);
    }

    //  내가 댓글 단 일기 총 개수
    public int countReplyDiariesByMemberId(Long memberId) {
        return diaryMapper.countReplyDiariesByMemberId(memberId);
    }

    //  다이어리 목록(다이어리 서비스쪽)
    public List<DiaryDTO> findAllByKeyword(Criteria criteria,Search search){
        return diaryMapper.selectAllByKeyword(criteria, search);
    }
    // 다이리 목록 개수(다이어리 서비스쪽)
    public int findCountAllByKeyword( Search search){
        return diaryMapper.selectCountAllByKeyword(search);
    }

    public void changeLikeCount(int diff,Long postId){
        diaryMapper.updateLikeCount(diff,postId);
    }

//    다이어리 검색 목록 개수
    public int searchDiaryCount( Search search){
        return diaryMapper.searchDiaryCount(search);
    }

    //  다이어리 저장
    public void save(DiaryVO diaryVO){
        diaryMapper.insert(diaryVO);
    }
//    다이어리 상세 가져오기
    public Optional<DiaryDTO> findByPostId(Long postId) {
        return diaryMapper.selectByPostId(postId);
    }

    //  다이어리 공개/비공개 변경
    public void updateSecret(Long postId, Secret secret){
        diaryMapper.updateSecret(postId,secret);
    }

    //   댓글 개수 증가 / 감소
    public void changeReplyCount(int count,Long postId){
        diaryMapper.updateReplyCount(count,postId);
    }
    //    memberId로 다이어리 개수 조회
    public int countAllByMemberId(Long memberId) {
        return diaryMapper.selectCountDiaryAllByMemberId(memberId);
    }
    //    memberId로 다이어리  조회
    public List<DiaryDTO>  findDiaryAllByMemberId(Long memberId){
        return diaryMapper.selectDiaryAllByMemberId(memberId);
    }

    // 나의 다이어리 목록 조회 (무한스크롤)
    public List<MyDiaryDTO> findMyDiaryListByCriteria(Long memberId, ScrollCriteria criteria) {
        return diaryMapper.selectMyDiaryListByCriteria(memberId,criteria);
    }

    //  나의 다이어리 개수
    public int countMyDiariesByMemberId(Long memberId) {
        return diaryMapper.countMyDiariesByMemberId(memberId);
    }

    //  좋아요 개수 게시
    public String findLikeCountByPostId(Long postId){
        return diaryMapper.selectLikeCountByPostId(postId);
    }
}
