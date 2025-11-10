package com.example.crewstation.dto.diary;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@Getter
@Setter
@ToString
@EqualsAndHashCode(of="id")
public class MyDiaryDTO {
    private Long id;
    private Long postId;
    private String postTitle;
    private Long diaryId;
    private String mainImage;
    private Long memberId;
    private Long diaryPathId;
    private String postContent;
    private String createdDatetime;
    private String updatedDatetime;

    public String getFormattedCreatedDatetime() {
        return formatDateString(createdDatetime);
    }

    private String formatDateString(String datetime) {
        if (datetime == null || datetime.isBlank()) return "";

        try {
            // 정규식으로 소수점 이하 자릿수 보정
            if (datetime.contains(".")) {
                Pattern pattern = Pattern.compile("\\.(\\d{1,6})$");
                Matcher matcher = pattern.matcher(datetime);
                if (matcher.find()) {
                    String frac = matcher.group(1);
                    String padded = String.format("%-6s", frac).replace(' ', '0');
                    datetime = matcher.replaceAll("." + padded);
                }
            }

            DateTimeFormatter dbFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSSSS");
            LocalDateTime parsed = LocalDateTime.parse(datetime, dbFormat);
            return parsed.format(DateTimeFormatter.ofPattern("yyyy.MM.dd"));

        } catch (DateTimeParseException e1) {
            try {
                DateTimeFormatter fallback = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
                LocalDateTime parsed = LocalDateTime.parse(datetime, fallback);
                return parsed.format(DateTimeFormatter.ofPattern("yyyy.MM.dd"));
            } catch (Exception e2) {
                return datetime; // 포맷 실패 시 원본 반환
            }
        }
    }
}
