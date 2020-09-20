package com.anbai.sec.vuls.context;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 * 获取Spring上下文,Spring启动时会自动注入context
 *
 * @author yz
 */
@Component
public class SpringContext implements ApplicationContextAware {

	private static ApplicationContext context;

	public static ApplicationContext getContext() {
		return context;
	}

	/**
	 * 获取一个已经在Spring中注册的bean
	 *
	 * @param beanName
	 * @param <T>
	 * @return
	 */
	public static <T> T getBean(String beanName) {
		return (T) getContext().getBean(beanName);
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		context = applicationContext;
	}

}