package com.example.crewstation.repository.member;

import com.example.crewstation.domain.file.FileVO;
import com.example.crewstation.domain.file.member.MemberFileVO;
import com.example.crewstation.mapper.member.MemberFileMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
@Slf4j
public class MemberFileDAO {
    private final MemberFileMapper memberFileMapper;
    //    회원가입 시 주소
    public void save(MemberFileVO memberFileVO) {
        memberFileMapper.insert(memberFileVO);
    }

    // 멤버-파일 연결 삭제
    public void deleteMemberFile(Long memberId, Long fileId) {
        memberFileMapper.deleteMemberFile(memberId, fileId);
    }

}
