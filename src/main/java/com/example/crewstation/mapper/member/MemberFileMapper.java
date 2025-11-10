package com.example.crewstation.mapper.member;

import com.example.crewstation.domain.file.FileVO;
import com.example.crewstation.domain.file.member.MemberFileVO;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface MemberFileMapper {
    //    회원가입 시 프로필  insert
    public void insert(MemberFileVO memberFileVO);

    //  멤버-파일 연결 삭제
    public int deleteMemberFile(@Param("memberId") Long memberId, @Param("fileId") Long fileId);
}
