package com.example.crewstation.mapper.member;

import com.example.crewstation.common.enumeration.MemberProvider;
import com.example.crewstation.domain.member.MemberVO;
import com.example.crewstation.dto.member.*;
import com.example.crewstation.util.Criteria;
import com.example.crewstation.util.Search;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Optional;

@Mapper
public interface MemberMapper {
    //    회원가입
    public void insert(MemberVO memberVO);

    //    이메일 중복 검사
    public boolean selectEmail(String memberEmail);

    //    sns 회원가입
    public void insertSns(MemberVO memberVO);

    //    로그인
    public Optional<MemberDTO> selectForLogin(MemberDTO memberDTO);

    //    이메일로 조회
    public Optional<MemberDTO> selectMemberByMemberEmail(String memberEmail);

//    sns 조회
    public Optional<MemberDTO> selectMemberBySnsEmail(@Param("memberSocialEmail") String memberSocialEmail, @Param("provider") MemberProvider provider);

//  게스트 추가
    public void insertGuest(MemberDTO memberDTO);

//  멤버 프로필 조회용
    public Optional<MemberDTO> selectProfileById(@Param("memberId") Long memberId);

//    비밀번호 업데이트
    public void updatePassword(@Param("memberEmail") String memberEmail,@Param("memberPassword") String memberPassword);

//   별점 등록 시 케미지수 업데이트
    public void updateChemistryScore(@Param("sellerId") Long sellerId, @Param("rating") int rating);
//    회원 검색
    public List<MemberDTO> selectSearchMember(String search);

//    관리자 회원 목록
    public List<MemberDTO> findAdminMembers(@Param("search") Search search,
                                            @Param("limit") int limit,
                                            @Param("offset") int offset);
//    회원수 조회
    public int countAdminMembers(@Param("search") Search search);

//   관리자 상세 조회
    public MemberDTO findAdminMemberDetail(@Param("memberId") Long memberId);

    // 나의 판매내역 목록 조회
    public List<MySaleListDTO> selectSaleList(@Param("memberId") Long memberId,
                                            @Param("criteria") Criteria criteria,
                                            @Param("search") Search search);

//  나의 판매내역 상세 조회
    public MySaleDetailDTO selectSellerOrderDetails(
            @Param("sellerId") Long sellerId,
            @Param("paymentStatusId") Long paymentStatusId
    );

    // 전체 개수 조회 (페이징)
    public int selectSaleTotalCount(@Param("memberId") Long memberId,
                                    @Param("search") Search search);

//  나의 구매내역 상세
    public List<MyPurchaseDetailDTO>  selectMyPurchaseDetail(Long purchaseId);

//    월별 가입자 수
    public List<MemberStatics> selectMonthlyJoin();

//    오늘 가입자 수
    public int selectCountTodayJoin();

//    총 회원 수
    public int selectTotalMemberCount();

//    관리자 등록
    public void insertAdmin(MemberDTO memberDTO);


    //  내 정보 수정 정보조회
    public ModifyDTO selectMyInfo(Long memberId);

    // 내 정보 수정 업데이트
    public void updateMember(MemberVO memberVO);

    //    id로 멤버 조회
    public MemberDTO selectMemberById(Long memberId);

    //    마이페이지에서 프로필 조회용
    public MemberProfileDTO selectMyPageProfileById(Long memberId);

    //  탈퇴하기
    public void updateMemberStatusInactive(Long memberId);


}


