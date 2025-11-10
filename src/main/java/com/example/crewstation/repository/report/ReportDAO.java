package com.example.crewstation.repository.report;

import com.example.crewstation.common.enumeration.AccompanyStatus;
import com.example.crewstation.domain.report.ReportVO;
import com.example.crewstation.domain.report.post.ReportPostVO;
import com.example.crewstation.domain.report.reply.ReportReplyVO;
import com.example.crewstation.dto.report.ReportDTO;
import com.example.crewstation.dto.report.post.ReportPostDTO;
import com.example.crewstation.mapper.report.ReportMapper;
import com.example.crewstation.util.Criteria;
import com.example.crewstation.util.ScrollCriteria;
import com.example.crewstation.util.Search;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class ReportDAO {
    private final ReportMapper reportMapper;

    //  신고하기 추가
    public void saveReport(ReportDTO reportDTO){
        reportMapper.insertReport(reportDTO);
    };

    //  신고하기 연결부분 추가
    public void saveReportPost(ReportPostVO reportPostVO){
        reportMapper.insertReportPost(reportPostVO);
    }
    public void saveReportReply(ReportReplyVO reportReplyVO){
        reportMapper.insertReportReply(reportReplyVO);
    }

//    관리자 다이어리 신고 내역
    public List<ReportPostDTO> findAllReportDiaries(ScrollCriteria scrollCriteria) {
        return reportMapper.selectAllReportDiaries(scrollCriteria);
    }

//    관리자 다이어리 신고 갯수
    public int countAllReportDiaries() {
        return reportMapper.selectReportDiariesCount();
    }

//    게시글 숨김
    public void updatePostStatus(Long postId, String status) {
        reportMapper.updatePostStatus(postId, status);
    }

//    신고 처리 상태 변경
    public void updateReportProcessStatus(Long reportId, String status) {
        reportMapper.updateReportProcessStatus(reportId, status);
    }

//    관리자 기프트 신고 내역
    public List<ReportPostDTO> findAllReportGifts(ScrollCriteria scrollCriteria) {
        return reportMapper.selectAllReportGifts(scrollCriteria);
    }

//    관리자 기프트 신고 갯수
    public int countAllReportGifts() {
        return reportMapper.selectReportGiftsCount();
    }

//    관리자 동행 신고 내역
    public List<ReportPostDTO> accompanyReportList(ScrollCriteria scrollCriteria ,Search search) {
        return reportMapper.selectAllReportAccompany(scrollCriteria ,search);
    }

//    관리자 동행 신고 갯수
    public int countAllReportAccompany(AccompanyStatus accompanyStatus) {
        return reportMapper.selectReportAccompanyCount(accompanyStatus);
    }

}
