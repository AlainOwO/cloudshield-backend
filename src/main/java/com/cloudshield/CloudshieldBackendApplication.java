package com.cloudshield;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// This array completely blinds Spring Boot to any database dependencies
@SpringBootApplication(excludeName = {
        "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration",
        "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration"
})
public class CloudshieldBackendApplication {
    public static void main(String[] args) {
        SpringApplication.run(CloudshieldBackendApplication.class, args);
    }
}