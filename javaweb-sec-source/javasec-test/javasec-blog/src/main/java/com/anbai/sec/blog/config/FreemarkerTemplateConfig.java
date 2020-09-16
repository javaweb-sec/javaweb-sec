package com.anbai.sec.blog.config;

import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.view.freemarker.FreeMarkerConfigurer;
import org.springframework.web.servlet.view.freemarker.FreeMarkerViewResolver;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Freemarker 模板初始化配置
 * Created by yz on 2017/4/4.
 */
@Configuration
public class FreemarkerTemplateConfig {

	@Bean
	public PropertiesFactoryBean freemarkerConfiguration() {
		PropertiesFactoryBean factoryBean = new PropertiesFactoryBean();
		Properties            properties  = new Properties();

		factoryBean.setFileEncoding("UTF-8");

		properties.setProperty("tag_syntax", "auto_detect");
		properties.setProperty("template_update_delay", "2");
		properties.setProperty("default_encoding", "UTF-8");
		properties.setProperty("output_encoding", "UTF-8");
		properties.setProperty("locale", "zh_CN");
		properties.setProperty("date_format", "yyyy-MM-dd");
		properties.setProperty("time_format", "HH:mm:ss");
		properties.setProperty("datetime_format", "yyyy-MM-dd HH:mm:ss");

		factoryBean.setProperties(properties);

		return factoryBean;
	}

	/**
	 * Freemarker 自定义标签(变量)设置
	 *
	 * @return
	 */
	private Map<String, Object> getFreemarkerVariables() {
		Map<String, Object> freemarkerVariables = new HashMap<>();
		return freemarkerVariables;
	}

	@Bean
	public FreeMarkerConfigurer freemarkerConfig() {
		FreeMarkerConfigurer freemarkerConfig = new FreeMarkerConfigurer();

		freemarkerConfig.setTemplateLoaderPath("classpath:/templates/");
		freemarkerConfig.setDefaultEncoding("UTF-8");
		freemarkerConfig.setFreemarkerVariables(getFreemarkerVariables());

		return freemarkerConfig;
	}

	@Bean
	public FreeMarkerViewResolver viewResolver() {
		FreeMarkerViewResolver resolver = new FreeMarkerViewResolver();

		resolver.setViewNames("*.html");
		resolver.setContentType("text/html;charset=UTF-8");
		resolver.setExposeRequestAttributes(true);
		resolver.setExposeSessionAttributes(true);
		resolver.setExposeSpringMacroHelpers(true);
		resolver.setRequestContextAttribute("request");
		resolver.setCache(true);

		return resolver;
	}

}
