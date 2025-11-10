package com.example.crewstation.mapper.file;

import com.example.crewstation.domain.file.FileVO;
import com.example.crewstation.dto.file.FileDTO;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface FileMapper {
//    insert
    public void insertFile(FileVO fileVO);

//  파일 추가
    public void insert(FileDTO fileDTO);

//  파일 삭제
    public void delete(Long id);

//  파일 조회
    FileDTO selectOne(@Param("id") Long id);

//  멤버-파일 조회
    public FileDTO findProfileByMemberId(@Param("memberId") Long memberId);


}
