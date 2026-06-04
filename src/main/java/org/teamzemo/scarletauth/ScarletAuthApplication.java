package org.teamzemo.scarletauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.teamzemo.scarletauth.config.AppProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class ScarletAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(ScarletAuthApplication.class, args);
    }
}
