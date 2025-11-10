package com.example.crewstation.dto.member;

import lombok.*;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ToString
@EqualsAndHashCode(of = "id")
@NoArgsConstructor
public class MemberProfileDTO {
    private Long memberId;
    private String memberName;
    private String profileImage;
    private String filePath;
    private String socialImgUrl;
}
