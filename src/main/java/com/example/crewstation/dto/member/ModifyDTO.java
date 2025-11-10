package com.example.crewstation.dto.member;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ToString
@NoArgsConstructor
public class ModifyDTO {
    private Long memberId;
    private String memberEmail;
    private String memberName;
    private String memberBirth;
    private String memberPhone;
    private String memberAddress;
    private String zipCode;
    private String address;
    private String addressDetail;
    private String memberSocialUrl;
    private String socialImgUrl;
    private String memberSocialEmail;

    private String filePath;
    private String fileName;

    private MultipartFile profileFile;  // 업로드할 실제 파일
    private String memberProfileImg; // 프로필 조회용
}
