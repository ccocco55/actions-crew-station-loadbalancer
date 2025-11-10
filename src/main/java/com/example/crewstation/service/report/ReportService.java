package com.example.crewstation.service.report;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.domain.report.post.ReportPostVO;
import com.example.crewstation.domain.report.reply.ReportReplyVO;
import com.example.crewstation.dto.report.ReportDTO;
import com.example.crewstation.dto.report.post.ReportPostDTO;
import com.example.crewstation.util.ScrollCriteria;
import com.example.crewstation.util.Search;

import java.util.List;

public interface ReportService {

    //  신고하기
    public void report(Long postId, String reportContent, CustomUserDetails userDetails);

    public void reportReply(Long replyId, ReportDTO reportDTO,CustomUserDetails userDetails);

    //    관리자 다이어리 신고 목록
    public List<ReportPostDTO> getReportDiaries(int page);

    //    게시글 숨김
    public void hidePost(Long postId);

//    관리자 동행 신고 내역
    public List<ReportPostDTO> getReportAccompanies(Search search);

    default ReportPostVO toReportPostVO(ReportDTO reportDTO){
        return ReportPostVO.builder()
                .reportId(reportDTO.getId())
                .postId(reportDTO.getPostId()).build();
    }
    default ReportReplyVO toReportReplyVO(ReportDTO reportDTO){
        return ReportReplyVO.builder()
                .replyId(reportDTO.getReplyId())
                .reportId(reportDTO.getId()).build();
    }

    public void resolveReport(Long reportId);
}
