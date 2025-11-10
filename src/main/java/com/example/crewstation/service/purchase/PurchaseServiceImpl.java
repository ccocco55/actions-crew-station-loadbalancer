package com.example.crewstation.service.purchase;

import com.example.crewstation.aop.aspect.annotation.LogReturnStatus;
import com.example.crewstation.aop.aspect.annotation.LogStatus;
import com.example.crewstation.auth.CustomUserDetails;
import com.example.crewstation.common.enumeration.PaymentPhase;
import com.example.crewstation.common.enumeration.Type;
import com.example.crewstation.common.exception.PurchaseNotFoundException;
import com.example.crewstation.domain.file.section.FilePostSectionVO;
import com.example.crewstation.domain.post.PostVO;
import com.example.crewstation.domain.purchase.PurchaseVO;
import com.example.crewstation.dto.file.FileDTO;
import com.example.crewstation.dto.file.section.FilePostSectionDTO;
import com.example.crewstation.dto.member.MyPurchaseDetailDTO;
import com.example.crewstation.dto.payment.status.PaymentCriteriaDTO;
import com.example.crewstation.dto.post.PostDTO;
import com.example.crewstation.dto.post.section.SectionDTO;
import com.example.crewstation.dto.purchase.*;
import com.example.crewstation.repository.file.FileDAO;
import com.example.crewstation.repository.file.section.FilePostSectionDAO;
import com.example.crewstation.repository.payment.status.PaymentStatusDAO;
import com.example.crewstation.repository.post.PostDAO;
import com.example.crewstation.repository.purchase.PurchaseDAO;
import com.example.crewstation.repository.section.SectionDAO;
import com.example.crewstation.service.s3.S3Service;
import com.example.crewstation.util.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.Duration;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.IntStream;

@Service
@RequiredArgsConstructor
@Slf4j
public class PurchaseServiceImpl implements PurchaseService {
    private final PurchaseDAO purchaseDAO;
    private final S3Service s3Service;
    private final SectionDAO sectionDAO;
    private final PostDAO postDAO;
    private final FileDAO fileDAO;
    private final FilePostSectionDAO filePostSectionDAO;
    private final PaymentStatusDAO paymentStatusDAO;

    private final PurchaseTransactionService purchaseTransactionService;
    private final RedisTemplate<String, PurchaseDTO> purchaseRedisTemplate;
    private final RedisTemplate<String, Object> redisTemplate;

    @Override
    @LogReturnStatus
    public PurchaseCriteriaDTO getPurchases(Search search) {
        PurchaseCriteriaDTO purchaseCriteriaDTO = new PurchaseCriteriaDTO();
        int page = search.getPage();
        Criteria criteria = new Criteria(page, purchaseDAO.findCountAllByKeyWord(search));
        List<PurchaseDTO> purchases = purchaseDAO.findAllByKeyWord(criteria, search);
        purchases.forEach(purchase -> {
            purchase.setPurchaseProductPrice(PriceUtils.formatMoney(purchase.getPrice()));
            purchase.setFilePath(s3Service.getPreSignedUrl(purchase.getFilePath(), Duration.ofMinutes(5)));
            purchase.setLimitDateTime(DateUtils.calcLimitDateTime(purchase.getCreatedDatetime(), purchase.getPurchaseLimitTime()));
        });
        criteria.setHasMore(purchases.size() > criteria.getRowCount());
        if (criteria.isHasMore()) {
            purchases.remove(purchases.size() - 1);
        }
        purchaseCriteriaDTO.setPurchaseDTOs(purchases);
        purchaseCriteriaDTO.setCriteria(criteria);
        purchaseCriteriaDTO.setSearch(search);
        return purchaseCriteriaDTO;
    }

//    @Override
//    @Transactional(rollbackFor = Exception.class)
//    @Cacheable(value = "purchases", key = "'purchases_' + #postId")
//    @LogReturnStatus
//    public PurchaseDTO getPurchase(Long postId) {
//        purchaseDAO.increaseReadCount(postId);
//        Optional<PurchaseDTO> purchaseDetail = purchaseDAO.findByPostId(postId);
//        PurchaseDTO purchaseDTO = purchaseDetail.orElseThrow(PurchaseNotFoundException::new);
////
////        List<SectionDTO> sections = sectionDAO.findSectionsByPostId(postId);
////        sections.forEach(section -> {
////            section.setFilePath(s3Service.getPreSignedUrl(section.getFilePath(), Duration.ofMinutes(5)));
////        });
////
////        sections.sort(Comparator.comparing(SectionDTO::getImageType));
////        log.info(sections.toString());
//        log.info("{}",purchaseDTO.getPrice());
//        purchaseDTO.setPurchaseProductPrice(PriceUtils.formatMoney(purchaseDTO.getPrice()));
//        purchaseDTO.setLimitDateTime(DateUtils.calcLimitDateTime(purchaseDTO.getUpdatedDatetime(), purchaseDTO.getPurchaseLimitTime()));
////        purchaseDTO.setSections(sections);
//        return purchaseDTO;
//    }
    @Override
    @LogReturnStatus
    public PurchaseDTO getPurchase(Long id) {
        // 캐시 먼저 확인
        log.info(":::::::::::::::{}",purchaseRedisTemplate.opsForValue().get("purchase::purchases_" + id));
            PurchaseDTO cached = purchaseRedisTemplate.opsForValue().get("purchase::purchases_" + id);
        if (cached != null) {
            // 트랜잭션 시작하면서 조회수만 증가
            List<SectionDTO> sections = sectionDAO.findSectionsByPostId(cached.getPostId());
            if(cached.getFilePath() != null){
                cached.setFilePath(s3Service.getPreSignedUrl(cached.getFilePath(), Duration.ofMinutes(5)));
            }
            sections.forEach(section -> {
                section.setFilePath(s3Service.getPreSignedUrl(section.getFilePath(), Duration.ofMinutes(5)));
            });
            sections.sort(Comparator.comparing(SectionDTO::getImageType));
            cached.setSections(sections);
            return cached;
        }

        // 캐시에 없으면 트랜잭션으로 조회 + 증가 + 캐시 저장
        return purchaseTransactionService.getPurchaseFromDbAndCache(id);
    }



    @Override
    @Transactional(rollbackFor = Exception.class)
    @LogStatus
    public void write(PurchaseDTO purchaseDTO, List<MultipartFile> files) {
        FileDTO fileDTO = new FileDTO();
        FilePostSectionDTO sectionFileDTO = new FilePostSectionDTO();
        postDAO.savePost(purchaseDTO);
        PurchaseVO purchaseVO = toPurchaseVO(purchaseDTO);
        purchaseDAO.save(purchaseVO);
        IntStream.range(0, files.size()).forEach(i -> {
            MultipartFile file = files.get(i);
            if (file.getOriginalFilename().equals("")) {
                return;
            }
            Type type = Type.SUB;
            if (i == purchaseDTO.getThumbnail()) {
                type = Type.MAIN;
            }
            try {
                String s3Key = s3Service.uploadPostFile(file, getPath());
                String originalFileName = file.getOriginalFilename();
                String extension = "";

                if (originalFileName != null && originalFileName.contains(".")) {
                    extension = originalFileName.substring(originalFileName.lastIndexOf("."));
                }

                fileDTO.setFileName(UUID.randomUUID() + extension);
                fileDTO.setFilePath(s3Key);
                fileDTO.setFileSize(String.valueOf(file.getSize()));
                fileDTO.setFileOriginName(originalFileName);
                fileDAO.saveFile(fileDTO);
                sectionDAO.save(purchaseDTO);
                sectionFileDTO.setFileId(fileDTO.getId());
                sectionFileDTO.setImageType(type);
                sectionFileDTO.setPostSectionId(purchaseDTO.getPostSectionId());
                FilePostSectionVO vo = toSectionFileVO(sectionFileDTO);
                filePostSectionDAO.save(vo);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        });
        if(redisTemplate.opsForValue().get("gifts") !=null){
            redisTemplate.delete("gifts");
        }

    }

    @Override
    @Transactional(rollbackFor = Exception.class)
//    @CachePut(value = "purchases", key = "'purchases_' + #purchaseDTO.postId")
    @LogReturnStatus
    public PurchaseDTO update(PurchaseDTO purchaseDTO, Long[] deleteFiles, List<MultipartFile> multipartFiles) {
        FileDTO fileDTO = new FileDTO();
        Long section = -1L;
        FilePostSectionDTO sectionFileDTO = new FilePostSectionDTO();
        PurchaseVO purchaseVO = toPurchaseVO(purchaseDTO);
        PostVO postVO = toPostVO(purchaseDTO);
//      일단 상품 정보 업데이트
        purchaseDAO.update(purchaseVO);
//      슈퍼 키 부분 업데이트
        postDAO.update(postVO);

//        삭제 부분
        if (deleteFiles != null && deleteFiles.length > 0) {
            Arrays.stream(deleteFiles).forEach(sectionId -> {
                FilePostSectionDTO file = filePostSectionDAO.findPostSectionFileIdBySectionId(sectionId)
                        .orElseThrow(PurchaseNotFoundException::new);
                s3Service.deleteFile(file.getFilePath());
                filePostSectionDAO.delete(sectionId);
                fileDAO.delete(file.getFileId());
                sectionDAO.delete(sectionId);

            });
        }
//        새로운 이미지 추가 부분
        IntStream.range(0, multipartFiles.size()).forEach(i -> {
            MultipartFile file = multipartFiles.get(i);
            if (file.getOriginalFilename().equals("")) {
                return;
            }
            Type type = Type.SUB;
//           추가된 이미지에서 썸네일이 있을 때
            if (!purchaseDTO.isPrev() && purchaseDTO.getThumbnail() != null && purchaseDTO.getThumbnail().equals((long) i)) {
                type = Type.MAIN;
                filePostSectionDAO.updateImageType(purchaseDTO.getPrevMainImg(), Type.SUB);
            }
            try {
                String s3Key = s3Service.uploadPostFile(file, getPath());
                String originalFileName = file.getOriginalFilename();
                String extension = "";

                if (originalFileName != null && originalFileName.contains(".")) {
                    extension = originalFileName.substring(originalFileName.lastIndexOf("."));
                }

                fileDTO.setFileName(UUID.randomUUID() + extension);
                fileDTO.setFilePath(s3Key);
                fileDTO.setFileSize(String.valueOf(file.getSize()));
                fileDTO.setFileOriginName(originalFileName);
                fileDAO.saveFile(fileDTO);
                sectionDAO.save(purchaseDTO);
                sectionFileDTO.setFileId(fileDTO.getId());
                sectionFileDTO.setImageType(type);
                sectionFileDTO.setPostSectionId(purchaseDTO.getPostSectionId());
                FilePostSectionVO vo = toSectionFileVO(sectionFileDTO);
                filePostSectionDAO.save(vo);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        });

//      대표 이미지 변경 없을 시
        if (purchaseDTO.getThumbnail() == null) {
            section = purchaseDTO.getPrevMainImg();
            purchaseDTO.setThumbnail(section);
            sectionDAO.update(toPostSectionVO(purchaseDTO));
        } else if (purchaseDTO.isPrev() && !purchaseDTO.getThumbnail().equals(purchaseDTO.getPrevMainImg())) {

            filePostSectionDAO.updateImageType(purchaseDTO.getThumbnail(), Type.MAIN);
            filePostSectionDAO.updateImageType(purchaseDTO.getPrevMainImg(), Type.SUB);
            sectionDAO.update(toPostSectionVO(purchaseDTO));
        }

        if(purchaseRedisTemplate.opsForValue().get("purchase::purchases_" + purchaseDTO.getPostId()) !=null){
            purchaseRedisTemplate.delete("purchase::purchases_" + purchaseDTO.getPostId());
        }
        if(redisTemplate.opsForValue().get("gifts") !=null){
            redisTemplate.delete("gifts");
        }
        return purchaseDTO;
    }

    @Override
//    @CacheEvict(value = "purchases", key = "'purchases_' + #id")
    public void softDelete(Long id) {
        postDAO.updatePostStatus(id);
        if(purchaseRedisTemplate.opsForValue().get("purchase::purchases_" + id) !=null){
            purchaseRedisTemplate.delete("purchase::purchases_" + id);
        }
        if(redisTemplate.opsForValue().get("gifts") !=null){
            redisTemplate.delete("gifts");
        }

    }


    public String getPath() {
        LocalDate today = LocalDate.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy/MM/dd");
        return today.format(formatter);
    }

    // 나의 구매내역 목록 조회
    @Override
    public PurchaseListCriteriaDTO getPurchaseListByMemberId(Long memberId, ScrollCriteria scrollcriteria, Search search) {

        List<PurchaseListDTO> list = purchaseDAO.selectPurchaseList(memberId, scrollcriteria, search);

        int total = purchaseDAO.selectTotalCount(memberId, search);
        scrollcriteria.setTotal(total);

        // S3 presigned URL 변환
        list.forEach(dto -> {
            try {
                if (dto.getFilePath() != null && !dto.getFilePath().isBlank()) {
                    log.info("Before S3 convert filePath={}", dto.getFilePath());
                    String preSignedUrl = s3Service.getPreSignedUrl(dto.getFilePath(), Duration.ofMinutes(5));
                    dto.setFilePath(preSignedUrl);
                    log.info("After S3 convert preSignedUrl={}", preSignedUrl);
                }
            } catch (Exception e) {
                log.warn("S3 URL 변환 실패: {}", e.getMessage());
            }
        });

        // 결과 DTO 구성
        PurchaseListCriteriaDTO result = new PurchaseListCriteriaDTO();
        result.setPurchaseListDTOs(list);
        result.setScrollcriteria(scrollcriteria);
        result.setSearch(search);

        log.info("result.getPurchaseListDTOs() = {}", result.getPurchaseListDTOs());
        return result;
    }



    //  나의 구매내역 상세 조회
    @Override
    public MyPurchaseDetailDTO getMemberOrderDetails(Long memberId, Long paymentStatusId) {
        MyPurchaseDetailDTO detail = purchaseDAO.selectMemberOrderDetails(memberId, paymentStatusId);

        if (detail == null) {
            throw new RuntimeException("회원 구매내역을 찾을 수 없습니다. memberId=" + memberId + ", paymentStatusId=" + paymentStatusId);
        }

        // S3 프리사인 URL 변환
        if (detail.getMainImage() != null && !detail.getMainImage().isBlank()) {
            String preSignedUrl = s3Service.getPreSignedUrl(detail.getMainImage(), Duration.ofMinutes(5));
            detail.setMainImage(preSignedUrl);
        }

        return detail;
    }

    //  결제 상태 업데이트 추가
    @Override
    @Transactional
    public void updatePaymentStatus(Long paymentStatusId, PaymentPhase paymentPhase) {
        paymentStatusDAO.updatePaymentStatus(paymentStatusId, paymentPhase);
        log.info("결제 상태 업데이트 완료 -> paymentStatusId={}, phase={}", paymentStatusId, paymentPhase);
    }

}
