package com.example.crewstation.service.member;

import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.common.enumeration.PaymentPhase;
import com.example.crewstation.domain.address.AddressVO;
import com.example.crewstation.domain.file.FileVO;
import com.example.crewstation.domain.file.member.MemberFileVO;
import com.example.crewstation.domain.member.MemberVO;
import com.example.crewstation.dto.file.FileDTO;
import com.example.crewstation.dto.file.member.MemberFileDTO;
import com.example.crewstation.dto.member.*;
import com.example.crewstation.util.Criteria;
import com.example.crewstation.util.Search;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

public interface MemberService {
//    회원가입
    public void join(MemberDTO memberDTO, MultipartFile multipartFile);

//    이메일 중복 검사
    public boolean checkEmail(String memberEmail);

//    로그인
    public MemberDTO login(MemberDTO memberDTO);

//    회원 정보 조회
    public MemberDTO getMember(String memberEmail, String provider);

// sns 가입
    public void joinSns(MemberDTO memberDTO, MultipartFile multipartFile);

//  멤버 프로필 조회
    public Optional<MemberDTO> getMemberProfile(Long memberId);

//  비밀번호 변경
    public void resetPassword(String memberEmail, String memberPassword);

//  별점 등록 시 상태 및 케미지수 업데이트
    public void submitReview(Long sellerId, Long purchaseId, int rating);
//  회원 검색
    public List<MemberDTO> searchMember(String search);

//    관리자 회원 목록
    public MemberCriteriaDTO getMembers(Search search);

//    관리자 상세
    public MemberDTO getMemberDetail(Long memberId);

//  나의 판매내역 목록
    public MySaleListCriteriaDTO getSaleListByMemberId(Long memberId, Criteria criteria, Search search);

//   나의 판매내역 상세 조회
    public MySaleDetailDTO getSellerOrderDetails(Long sellerId, Long paymentStatusId);

//    관리자 회원 통계 자료
    public MemberAdminStatics getStatics();

//    관리자 등록
    public void joinAdmin(MemberDTO memberDTO);


//  판매 상태 업데이트
    public void updateSaleStatus(Long memberId, Long paymentStatusId, PaymentPhase paymentPhase);

//  내 정보 수정 정보조회
    public ModifyDTO getMemberInfo(CustomUserDetails customUserDetails);

//  내 정보 수정 업데이트
    public void updateMyInfo(ModifyDTO modifyDTO,MultipartFile multipartFile);

//    id로 멤버 조회
    public MemberDTO getProfileMember(Long memberId);

//  마이페이지에서 내 프로필 조회용
    public MemberProfileDTO getMyPageProfile(CustomUserDetails customUserDetails);

    // 회원 비활성화 처리
    public void deactivateMember(Long memberId);

    default MemberVO toVO(MemberDTO memberDTO) {
        return MemberVO.builder()
                .id(memberDTO.getId())
                .memberName(memberDTO.getMemberName())
                .memberPhone(memberDTO.getMemberPhone())
                .memberEmail(memberDTO.getMemberEmail())
                .memberSocialUrl(memberDTO.getMemberSocialUrl())
                .memberBirth(memberDTO.getMemberBirth())
                .memberGender(memberDTO.getMemberGender())
                .memberMbti(memberDTO.getMemberMbti())
                .memberPassword(memberDTO.getMemberPassword())
                .memberStatus(memberDTO.getMemberStatus())
                .memberProvider(memberDTO.getMemberProvider())
                .socialImgUrl(memberDTO.getSocialImgUrl())
                .memberSocialEmail(memberDTO.getMemberSocialEmail())
                .memberDescription(memberDTO.getMemberDescription())
                .memberRole(memberDTO.getMemberRole())
                .createdDatetime(memberDTO.getCreatedDatetime())
                .updatedDatetime(memberDTO.getUpdatedDatetime())
                .build();
    }

    default AddressVO toVO(AddressDTO addressDTO) {
        return AddressVO.builder()
                .id(addressDTO.getId())
                .address(addressDTO.getAddress())
                .addressDetail(addressDTO.getAddressDetail())
                .addressZipCode(addressDTO.getAddressZipCode())
                .memberId(addressDTO.getMemberId())
                .createdDatetime(addressDTO.getCreatedDatetime())
                .updatedDatetime(addressDTO.getUpdatedDatetime())
                .build();
    }

    default FileVO toVO(FileDTO fileDTO) {
        return FileVO.builder()
                .id(fileDTO.getId())
                .fileOriginName(fileDTO.getFileOriginName())
                .fileName(fileDTO.getFileName())
                .filePath(fileDTO.getFilePath())
                .fileSize(fileDTO.getFileSize())
                .createdDatetime(fileDTO.getCreatedDatetime())
                .updatedDatetime(fileDTO.getUpdatedDatetime())
                .build();
    }

    default MemberFileVO toVO(MemberFileDTO memberfileDTO) {
        return MemberFileVO.builder()
                .fileId(memberfileDTO.getFileId())
                .memberId(memberfileDTO.getMemberId())
                .build();
    }

    public void deleteCache (String keyName);

    default MemberVO toVO(ModifyDTO modifyDTO) {
        return MemberVO.builder()
                .id(modifyDTO.getMemberId())
                .memberEmail(modifyDTO.getMemberEmail())
                .memberPhone(modifyDTO.getMemberPhone())
                .memberSocialUrl(modifyDTO.getMemberSocialUrl())
                .build();
    }
}

