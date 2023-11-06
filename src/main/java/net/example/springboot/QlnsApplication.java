package net.example.springboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class QlnsApplication {
	public static void main(String[] args) {
		SpringApplication.run(QlnsApplication.class, args);
	}
}
