package com.example.crewstation.dto.diary;


import com.example.crewstation.util.ScrollCriteria;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.List;

@Getter
@Setter
@ToString
public class MyDiaryCriteriaDTO {
    private List<MyDiaryDTO> myDiaryDTOs;
    private ScrollCriteria criteria;
}
