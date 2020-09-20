package com.anbai.sec.vuls.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan("com.anbai.sec.vuls.*")
public class JavaSecTestSpringBootApplication {

	public static void main(String[] args) {
		SpringApplication.run(JavaSecTestSpringBootApplication.class, args);
	}

}
