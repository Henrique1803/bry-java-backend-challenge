package br.com.bry.challenge;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class BryChallengeApplication {

    public static void main(String[] args) {
        SpringApplication.run(BryChallengeApplication.class, args);
    }
}
