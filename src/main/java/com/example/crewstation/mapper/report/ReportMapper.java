package com.example.crewstation.mapper.report;

import com.example.crewstation.common.enumeration.AccompanyStatus;
import com.example.crewstation.domain.report.ReportVO;
import com.example.crewstation.domain.report.post.ReportPostVO;
import com.example.crewstation.domain.report.reply.ReportReplyVO;
import com.example.crewstation.dto.post.PostDTO;
import com.example.crewstation.dto.report.ReportDTO;
import com.example.crewstation.dto.report.post.ReportPostDTO;
import com.example.crewstation.util.Criteria;
import com.example.crewstation.util.ScrollCriteria;
import com.example.crewstation.util.Search;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface ReportMapper {
//  신고하기 추가
    public void insertReport(ReportDTO reportDTO);
//  신고하기 연결부분 추가
    public void insertReportPost(ReportPostVO reportPostVO);

    public void insertReportReply(ReportReplyVO reportReplyVO);

//    관리자 다이어리 신고 내역
    public List<ReportPostDTO> selectAllReportDiaries(ScrollCriteria scrollCriteria);

//    관리자 다이어리 신고 갯수
    public int selectReportDiariesCount();

//    게시글 숨김
    public void updatePostStatus(@Param("postId") Long postId, @Param("status") String status);

//    신고 처리 상태 변경
    public void updateReportProcessStatus(@Param("reportId") Long reportId, @Param("status") String status);

//    관리자 기프트 신고 내역
    public List<ReportPostDTO> selectAllReportGifts(ScrollCriteria scrollCriteria);

//    관리자 기프트 신고 갯수
    public int selectReportGiftsCount();

//    관리자 롱크루 신고 내역
    public List<ReportPostDTO> selectAllReportAccompany(@Param("scrollCriteria") ScrollCriteria scrollCriteria, @Param("search") Search search);

//    관리자 롱크루 신고 갯수
    public int selectReportAccompanyCount(AccompanyStatus accompanyStatus);

}
