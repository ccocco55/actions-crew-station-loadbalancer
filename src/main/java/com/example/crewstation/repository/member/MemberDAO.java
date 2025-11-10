package com.example.crewstation.repository.member;

import com.example.crewstation.common.enumeration.MemberProvider;
import com.example.crewstation.domain.member.MemberVO;
import com.example.crewstation.dto.member.*;
import com.example.crewstation.mapper.member.MemberMapper;
import com.example.crewstation.util.Criteria;
import com.example.crewstation.util.Search;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
@Slf4j
public class MemberDAO {
    private final MemberMapper memberMapper;

    //    회원가입
    public void save(MemberVO memberVO) {
        memberMapper.insert(memberVO);
    }

    //  이메일 중복 검사
    public boolean checkEmail(String memberEmail) {
        return memberMapper.selectEmail(memberEmail);
    }

    //    로그인
    public Optional<MemberDTO> findForLogin(MemberDTO memberDTO) {
        return memberMapper.selectForLogin(memberDTO);
    }

    //    이메일로 회원 조회
    public Optional<MemberDTO> findByMemberEmail(String memberEmail) {
        return memberMapper.selectMemberByMemberEmail(memberEmail);
    }

    //    sns 회원가입
    public void saveSns(MemberVO memberVO) {
        memberMapper.insertSns(memberVO);
    }

    //    sns 회원 조회
    public Optional<MemberDTO> findBySnsEmail(String snsEmail, MemberProvider provider) {
        return memberMapper.selectMemberBySnsEmail(snsEmail, provider);
    }

    //  게스트 추가
    public void saveGuest(MemberDTO memberDTO) {
        memberMapper.insertGuest(memberDTO);
    }

    //  멤버 프로필 조회
    public Optional<MemberDTO> selectProfileById(Long memberId) {
        return memberMapper.selectProfileById(memberId);
    }

    //    비밀번호 업데이트
    public void updatePassword(String memberEmail, String memberPassword) {
        memberMapper.updatePassword(memberEmail, memberPassword);
    }

    //    별점 등록 시 케미지수 업데이트
    public void updateChemistryScore(Long sellerId, int rating) {
        memberMapper.updateChemistryScore(sellerId, rating);
    }
    //    회원 검색
    public List<MemberDTO> findSearchMember(String search){
        return memberMapper.selectSearchMember(search);
    }

//    관리자 회원 목록
    public List<MemberDTO> findAdminMembers(Search search, int limit, int offset){
        return memberMapper.findAdminMembers(search, limit, offset);
    }

//    회원 수
    public int countAdminMembers(Search search) {
        return memberMapper.countAdminMembers(search);
    }

//    관리자 회원 상세 목록
    public MemberDTO findAdminMemberDetail(Long memberId) {
        return memberMapper.findAdminMemberDetail(memberId);
    }

    //  판매 내역 목록 조회
    public List<MySaleListDTO> selectSaleList(Long memberId, Criteria criteria, Search search) {
        return memberMapper.selectSaleList(memberId, criteria, search);
    }

    // 판매 내역 상세 조회
    public MySaleDetailDTO selectSellerOrderDetails(Long sellerId, Long paymentStatusId) {
        return memberMapper.selectSellerOrderDetails(sellerId, paymentStatusId);
    }

    //  전체 개수 조회
    public int selectSaleTotalCount(Long memberId, Search search) {
        return memberMapper.selectSaleTotalCount(memberId, search);
    }

//    월별 가입자 수
        public List<MemberStatics> findMonthlyJoin() {
            return memberMapper.selectMonthlyJoin();
        }

//    오늘 가입자 수
    public int selectCountTodayJoin() {
        return memberMapper.selectCountTodayJoin();
    }

//    총 회원 수
    public int selectTotalMemberCount() {
        return memberMapper.selectTotalMemberCount();
    }

//    관리자 등록
    public void insertAdmin(MemberDTO memberDTO){
        memberMapper.insertAdmin(memberDTO);
    }


//  내 정보 수정 정보조회
    public ModifyDTO selectMemberInfo(Long memberId) {
        return memberMapper.selectMyInfo(memberId);
    }

//  내 정보 수정 업데이트
    public void updateMember(MemberVO memberVO) {
        memberMapper.updateMember(memberVO);
    }

    public MemberProfileDTO selectMyPageProfileById(Long memberId) {
        return memberMapper.selectMyPageProfileById(memberId);
    }


//    id로 멤버 조회
    public MemberDTO findMemberById(Long memberId){
       return memberMapper.selectMemberById(memberId);
    };

//  탈퇴하기
    public void updateMemberStatusInactive(Long memberId)  {
        memberMapper.updateMemberStatusInactive(memberId);
    }

}
