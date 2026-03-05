package cms;

import java.security.SecureRandom;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test-mail")
public class MailController {

    private final JavaMailSender mailSender;

    public MailController(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    // ===== OTP Generator =====
    private String generateOtp() {
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    // ===== Send OTP API =====
    @GetMapping("/send")
    public String sendMail(@RequestParam String to) {

        String otp = generateOtp();

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("CMS Portal - OTP Verification");
        message.setText(
                "Your OTP is: " + otp +
                "\n\nValid for 5 minutes." +
                "\nDo not share this OTP."
        );

        mailSender.send(message);

        return "OTP Sent Successfully!";
    }
}