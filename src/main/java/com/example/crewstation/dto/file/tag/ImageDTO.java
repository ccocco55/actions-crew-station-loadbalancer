package com.example.crewstation.dto.file.tag;


import com.example.crewstation.common.enumeration.Type;
import com.example.crewstation.dto.post.file.tag.PostFileTagDTO;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Component
@Getter
@Setter
@ToString
public class ImageDTO {
    private MultipartFile image;
    private Long postId;
    private Type thumbnail;
    private Long postSectionId;
    private Long fileId;
    private String postContent;
    private List<PostFileTagDTO> tags;
}
