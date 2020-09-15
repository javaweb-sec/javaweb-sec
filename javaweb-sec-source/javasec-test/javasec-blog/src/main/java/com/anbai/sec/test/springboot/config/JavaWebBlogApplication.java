package com.anbai.sec.test.springboot.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/**
 * @author yz
 */
@SpringBootApplication(scanBasePackages = "com.anbai.sec.test.springboot.*")
public class JavaWebBlogApplication extends SpringBootServletInitializer {

	public static void main(String[] args) {
		SpringApplication.run(JavaWebBlogApplication.class, args);
	}

	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
		return builder.sources(JavaWebBlogApplication.class);
	}

}
