package com.example.crewstation.service.banner;

import com.example.crewstation.aop.aspect.annotation.LogReturnStatus;
import com.example.crewstation.dto.banner.BannerDTO;
import com.example.crewstation.dto.file.FileDTO;
import com.example.crewstation.repository.banner.BannerDAO;
import com.example.crewstation.repository.file.FileDAO;
import com.example.crewstation.service.s3.S3Service;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.Duration;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;


@Service
@RequiredArgsConstructor
@Slf4j
public class BannerServiceImpl implements BannerService {
    private final BannerDAO bannerDAO;
    private final S3Service s3Service;
    private final BannerTransactionService bannerTransactionService;
    private final FileDAO fileDAO;

    @Override
    @Transactional(rollbackFor = Exception.class)
//    @LogReturnStatus
    public List<BannerDTO> getBanners(int limit) {
        List<BannerDTO> banners = bannerDAO.getBanners(limit);
        if (!banners.isEmpty()) {
            banners.forEach(banner -> {
                String filePath = banner.getFilePath();
                String presignedUrl = s3Service.getPreSignedUrl(filePath, Duration.ofMinutes(5));
                log.info(presignedUrl);
                banner.setUrl(presignedUrl);
            });
        }
        return banners;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @LogReturnStatus
    public void insertBannerFile(BannerDTO bannerDTO, List<MultipartFile> files) {
        FileDTO fileDTO = new FileDTO();
        bannerDAO.insertBanner(bannerDTO);
        if (files == null || files.isEmpty()) {
            return;
        }

        IntStream.range(0, files.size()).forEach(i -> {
            MultipartFile file = files.get(i);
            if (file.getOriginalFilename().equals("")) {
                return;
            }
            try {
                String originalFilename = file.getOriginalFilename();
                String extension = "";
                fileDTO.setFilePath(getPath());
                String s3Key = s3Service.uploadPostFile(file, fileDTO.getFilePath());

                if (originalFilename != null && originalFilename.contains(".")) {
                    extension = originalFilename.substring(originalFilename.lastIndexOf("."));
                }


                fileDTO.setFileName(UUID.randomUUID() + extension);
                fileDTO.setFilePath(s3Key);
                fileDTO.setFileSize(String.valueOf(file.getSize()));
                fileDTO.setFileOriginName(originalFilename);
                fileDAO.saveFile(fileDTO);

                log.info("{}----------------------------------------", bannerDTO.getBannerId());

                bannerDAO.insertBannerFile(bannerDTO.getBannerId(), fileDTO.getId());

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }


    @Override
    @Transactional(rollbackFor = Exception.class)
    @LogReturnStatus
    public void updateBanner(BannerDTO bannerDTO, Long[] deleteFiles, List<MultipartFile> multipartFiles) {

        bannerDAO.updateBannerFile(bannerDTO);

        if (deleteFiles != null && deleteFiles.length > 0) {
            Arrays.stream(deleteFiles).forEach(fileId -> {
                if (fileId == null) return;

                bannerDAO.deleteBannerFileLink(bannerDTO.getBannerId(), fileId);

                FileDTO found = fileDAO.findById(fileId);
                if (found != null && found.getFilePath() != null) {
                    try {
                        s3Service.deleteFile(found.getFilePath());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }

                fileDAO.delete(fileId);
            });
        }
        // 신규 파일 추가
        if (multipartFiles != null && !multipartFiles.isEmpty()) {
            IntStream.range(0, multipartFiles.size()).forEach(i -> {
                MultipartFile file = multipartFiles.get(i);
                if (file == null || file.isEmpty()) {
                    return;
                }
                try {
                    String originalFilename = file.getOriginalFilename();
                    if (originalFilename == null) originalFilename = "";

                    String extension = "";
                    int dot = originalFilename.lastIndexOf('.');
                    if (dot >= 0 && dot < originalFilename.length() - 1) {
                        extension = originalFilename.substring(dot + 1).trim().toLowerCase();
                    }

                    String fileName = UUID.randomUUID() + extension;
                    String s3Key = s3Service.uploadPostFile(file, fileName);

                    FileDTO fileDTO = new FileDTO();
                    fileDTO.setFileName(fileName);
                    fileDTO.setFilePath(s3Key);
                    fileDTO.setFileSize(String.valueOf(file.getSize()));
                    fileDTO.setFileOriginName(originalFilename);
                    fileDAO.saveFile(fileDTO);

                    bannerDAO.insertBannerFile(bannerDTO.getBannerId(), fileDTO.getId());

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void deleteBanner(Long id) {
        if (id == null) return;

        List<FileDTO> files = bannerDAO.findFilesByBannerId(id);
        bannerDAO.deleteAllBannerFiles(id);

        if (files != null) {
            for (FileDTO fileDTO : files) {
                if (fileDTO == null || fileDTO.getId() == null) continue;
                try {
                    if (fileDTO.getFilePath() != null) {
                        s3Service.deleteFile(fileDTO.getFilePath());
                    }
                } catch (Exception e) {
                }
                fileDAO.delete(fileDTO.getId());
            }
        }
        bannerDAO.deleteBanner(id);
    }

    public String getPath() {
        LocalDate today = LocalDate.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy/MM/dd");
        return today.format(formatter);
    }

}










