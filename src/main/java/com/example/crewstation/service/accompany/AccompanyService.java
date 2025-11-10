package com.example.crewstation.service.accompany;


import com.example.crewstation.dto.accompany.AccompanyCriteriaDTO;
import com.example.crewstation.dto.accompany.AccompanyDTO;
import com.example.crewstation.dto.report.post.ReportPostDTO;
import com.example.crewstation.util.Criteria;
import com.example.crewstation.util.Search;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface AccompanyService {
    public List<AccompanyDTO> getAccompanies(int limit);

    public AccompanyCriteriaDTO getSearchAccompanies(Search search);

//    관리자 동행 신고 목록
    public List<ReportPostDTO> getReportAccompaniesList(Search search);

    //    게시글 숨김
    public void hidePost(Long postId);

//    게시글 신고 처리
    public void resolveReport(Long reportId);

}
