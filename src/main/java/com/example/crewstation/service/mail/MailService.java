package com.example.crewstation.service.mail;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service
@RequiredArgsConstructor
public class MailService {
    private final JavaMailSender javaMailSender;

    public String sendMail(String mail) throws MessagingException {
        String code = createCode();

        String receiver = mail;
        String sender = "ccocco55@gmail.com";
        String title = "인증";

        StringBuilder body = new StringBuilder();
        body.append("<html>");
        body.append("<body style='margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background:#f4f6f8;'>");

        body.append("<div style='max-width:480px;margin:40px auto;background:#ffffff;border-radius:8px;padding:24px;"
                + "border:1px solid #e5e7eb;text-align:center;'>");

        body.append("<h1 style='font-size:20px;color:#0b63d0;margin-bottom:12px;'>crew station 이메일 인증</h1>");
        body.append("<p style='font-size:14px;color:#374151;margin-bottom:20px;'>비밀번호 재설정을 위한 인증 코드입니다.</p>");

        body.append("<div style='display:inline-block;padding:14px 20px;border:1px dashed #94a3b8;"
                + "background:#f8fafc;border-radius:6px;margin-bottom:20px;'>");
        body.append("<span style='font-size:26px;font-weight:bold;letter-spacing:4px;color:#0b63d0;'>");
        body.append(code);
        body.append("</span></div>");

        body.append("<p style='font-size:12px;color:#6b7280;margin-top:16px;'>해당 코드를 타인과 공유하지 말아주세요.</p>");

        body.append("</div>");
        body.append("</body></html>");

        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

        mimeMessageHelper.setFrom(sender);
        mimeMessageHelper.setTo(receiver);
        mimeMessageHelper.setSubject(title);
        mimeMessageHelper.setText(body.toString(), true);
        javaMailSender.send(mimeMessage);

        return code;
    }

//    코드 생성
    private String createCode(){
        String codes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String code = "";
        Random random = new Random();

        for(int i=0; i<10; i++){
            code += codes.charAt(random.nextInt(codes.length()));
        }

        return code;
    }
}















