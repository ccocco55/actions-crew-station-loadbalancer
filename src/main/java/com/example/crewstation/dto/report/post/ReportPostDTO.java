package com.example.crewstation.dto.report.post;

import com.example.crewstation.common.enumeration.ProcessStatus;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ToString
@EqualsAndHashCode(of="reportId")
public class ReportPostDTO {
    private Long reportId;
    private Long postId;

    private String reportContent;
    private String postTitle;
    private String createdDatetime;
    private String reporterEmail;
    private String reporterSocialEmail;
    private String writerEmail;
    private String writerSocialEmail;
    private ProcessStatus processStatus;
    private String accompanyStatus;
}
