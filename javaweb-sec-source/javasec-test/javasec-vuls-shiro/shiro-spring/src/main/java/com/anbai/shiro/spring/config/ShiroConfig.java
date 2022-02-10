package com.anbai.shiro.spring.config;

import org.apache.shiro.spring.config.ShiroAnnotationProcessorConfiguration;
import org.apache.shiro.spring.config.ShiroBeanConfiguration;
import org.apache.shiro.spring.web.config.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * @author su18
 */
@Configuration

@Import({ShiroBeanConfiguration.class,
		ShiroAnnotationProcessorConfiguration.class,
		ShiroWebConfiguration.class,
		ShiroWebFilterConfiguration.class,
		ShiroRequestMappingConfig.class
})
public class ShiroConfig {

	@Bean
	MyRealm realm() {
		return new MyRealm();
	}

//	@Bean
//	RememberMeManager rememberMeManager() {
//		return new CookieRememberMeManager();
//	}
//
//
//	@Bean
//	SecurityManager mySecurityManager(MyRealm realm, RememberMeManager rememberMeManager) {
//		DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
//		manager.setRealm((Realm) realm);
//		manager.setRememberMeManager(rememberMeManager);
//		return manager;
//	}
//
//	@Bean(name = {"shiroFilter"})
//	ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager mySecurityManager) {
//		ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
//		bean.setSecurityManager(mySecurityManager);
//		bean.setLoginUrl("/index/login");
//		bean.setUnauthorizedUrl("/index/unauth");
//		LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
//		map.put("/index/user", "authc");
////		map.put("/audit/list", "authc, perms[\"audit:list\"]");
//		map.put("/admin/*", "authc, roles[admin]");
//		map.put("/audit/*", "authc");
//		map.put("/logout", "logout");
//		bean.setFilterChainDefinitionMap(map);
//		return bean;
//	}

	@Bean
	public ShiroFilterChainDefinition shiroFilterChainDefinition() {
		DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();

		chainDefinition.addPathDefinition("/admin/*", "authc, roles[admin]");

		chainDefinition.addPathDefinition("/audit/list", "authc");

		chainDefinition.addPathDefinition("/audit/*", "anon");

		chainDefinition.addPathDefinition("/logout", "logout");
		return chainDefinition;
	}

}