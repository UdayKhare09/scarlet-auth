package org.teamzemo.scarletauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.teamzemo.scarletauth.config.AppProperties;

import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
@EnableFeignClients
public class ScarletAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(ScarletAuthApplication.class, args);
    }
}
