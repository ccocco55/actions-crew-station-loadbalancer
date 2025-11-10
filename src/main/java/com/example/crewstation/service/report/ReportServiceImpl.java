package com.example.crewstation.service.report;

import com.example.crewstation.aop.aspect.annotation.LogStatus;
import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.common.enumeration.ProcessStatus;
import com.example.crewstation.common.enumeration.Status;
import com.example.crewstation.common.exception.MemberNotFoundException;
import com.example.crewstation.common.exception.PostNotActiveException;
import com.example.crewstation.dto.report.ReportDTO;
import com.example.crewstation.dto.report.post.ReportPostDTO;
import com.example.crewstation.repository.post.PostDAO;
import com.example.crewstation.repository.report.ReportDAO;
import com.example.crewstation.util.ScrollCriteria;
import com.example.crewstation.util.Search;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class ReportServiceImpl implements ReportService {
    private final ReportDAO reportDAO;


    private final PostDAO postDAO;

    @Override
    @Transactional(rollbackFor = Exception.class)
//    @LogStatus
    public void report(Long postId, String reportContent, CustomUserDetails userDetails) {
        ReportDTO reportDTO = new ReportDTO();
        boolean isExist = postDAO.isActivePost(postId);
        log.info("{}",isExist);
        log.info("dasdjakdjaldjaldjasjd{}",reportContent);
//        log.info("{}",reportDTO.toString());

        if(!isExist){
            throw new PostNotActiveException("이미 삭제된 상품입니다.");
        }
        if(userDetails == null){
            throw new MemberNotFoundException("로그인 후 사용 가능");
        }
        reportDTO.setPostId(postId);
        reportDTO.setReportContent(reportContent);
        reportDTO.setMemberId(userDetails.getId());
        reportDAO.saveReport(reportDTO);

        reportDAO.saveReportPost(toReportPostVO(reportDTO));
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @LogStatus
    public void reportReply(Long replyId,ReportDTO reportDTO,CustomUserDetails userDetails) {

        boolean isExist = postDAO.isActivePost(reportDTO.getPostId());
        log.info("{}",isExist);
        log.info("{}",reportDTO.toString());

        if(!isExist){
            throw new PostNotActiveException("이미 삭제된 다이어리입니다.");
        }
        if(userDetails == null){
            throw new MemberNotFoundException("로그인 후 사용 가능");
        }
        reportDTO.setMemberId(userDetails.getId());
        reportDTO.setReplyId(replyId);
        reportDAO.saveReport(reportDTO);
        reportDAO.saveReportReply(toReportReplyVO(reportDTO));
    }

    @Override
    public List<ReportPostDTO> getReportDiaries(int page) {
        ScrollCriteria scrollCriteria = new ScrollCriteria(page, 10);
//        log.info("스크롤 페이지 번호 = {}", scrollCriteria.getPage());
        return reportDAO.findAllReportDiaries(scrollCriteria);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void hidePost(Long postId) {
        log.info("게시글 숨김 postId={}", postId);
        reportDAO.updatePostStatus(postId, Status.INACTIVE.getValue());
    }

    @Override
    public List<ReportPostDTO> getReportAccompanies(Search search) {
        ScrollCriteria scrollCriteria = new ScrollCriteria(search.getPage(), 10);
        scrollCriteria.setTotal(reportDAO.countAllReportAccompany(search.getAccompanyStatus()));
        return reportDAO.accompanyReportList(scrollCriteria, search);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void resolveReport(Long reportId) {
        log.info("신고 처리 상태 변경 reportId={}", reportId);
        reportDAO.updateReportProcessStatus(reportId, ProcessStatus.RESOLVED.getValue());
    }

}
