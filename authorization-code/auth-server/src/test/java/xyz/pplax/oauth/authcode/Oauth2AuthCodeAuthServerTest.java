package xyz.pplax.oauth.authcode;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
public class Oauth2AuthCodeAuthServerTest {

    @Test
    public void testA() {
        System.out.println(new BCryptPasswordEncoder().encode("client-a-secret"));
    }

}
