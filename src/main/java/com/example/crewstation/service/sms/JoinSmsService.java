package com.example.crewstation.service.sms;

import com.example.crewstation.common.exception.SmsSendFailException;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.nurigo.sdk.NurigoApp;
import net.nurigo.sdk.message.model.Message;
import net.nurigo.sdk.message.request.SingleMessageSendingRequest;
import net.nurigo.sdk.message.response.SingleMessageSentResponse;
import net.nurigo.sdk.message.service.DefaultMessageService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service
@RequiredArgsConstructor
@Slf4j
public class JoinSmsService {

    //        각자 api key 입력
    @Value("${sms.api.access}")
    private String apiKey;
    @Value("${sms.api.secret}")
    private String apiSecret;

    private DefaultMessageService messageService;

    @PostConstruct
    private void init(){
        this.messageService = NurigoApp.INSTANCE.initialize(apiKey, apiSecret, "https://api.coolsms.co.kr");
    }

    //    코드 생성
    private String createCode(){
        // 랜덤 숫자 5자리
        Random random = new Random();
        int rand = random.nextInt(100000); // 0 ~ 99999
        String randCode = String.format("%05d", rand);
        // 최종 코드
        String code = randCode;

        return code;
    }

    public String send(String phoneNumber) {
        String code = createCode();
        Message message = new Message();
        message.setTo(phoneNumber);
        message.setFrom("01083688745");
        message.setText("Crew Station 회원가입 인증 번호: " + code);
        try {
//            SingleMessageSentResponse response = this.messageService.sendOne(new SingleMessageSendingRequest(message));
//            log.info("Sending sms message to phone number " + response);
            log.info("code {}:::::::::", code);
        } catch (Exception e) {
            log.info("apikey {}", apiKey);
            log.info("apikey 길이 {}", apiKey.length());
            log.error("Failed to send sms messag", e);
            throw new SmsSendFailException("SMS 전송 실패했습니다.");
        }
        return code;
    }
}
