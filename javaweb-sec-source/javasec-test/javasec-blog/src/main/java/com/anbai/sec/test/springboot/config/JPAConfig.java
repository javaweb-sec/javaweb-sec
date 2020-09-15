package com.anbai.sec.test.springboot.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Created by yz on 2017/4/7.
 */
@Configuration
@EnableTransactionManagement
@EntityScan(basePackages = "com.anbai.sec.test.springboot.entity")
@EnableJpaRepositories(basePackages = "com.anbai.sec.test.springboot.repository")
public class JPAConfig {

}