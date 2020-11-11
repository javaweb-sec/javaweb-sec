/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import java.util.Set;

/**
 * 灵蜥Hook类配置
 * <p>
 * Creator: yz
 * Date: 2019-06-20
 */
public abstract class RASPHookConfig {

	protected Class<?> invokeClass;

	public RASPHookConfig(Class<?> invokeClass) {
		this.invokeClass = invokeClass;

		initHookConfigs();// 初始化Hook配置
	}

	public Class<?> getInvokeClass() {
		return invokeClass;
	}

	/**
	 * 初始化Hook配置
	 */
	public abstract void initHookConfigs();

	/**
	 * 获取Hook的类名
	 *
	 * @return
	 */
	public abstract String getHookClassName();

	/**
	 * 获取Hook的父类名
	 *
	 * @return
	 */
	public abstract String getHookSuperClassName();

	/**
	 * 获取Hook的类注解
	 *
	 * @return
	 */
	public abstract String[] getHooKClassAnnotations();

	/**
	 * 获取Hook的方法注解
	 *
	 * @return
	 */
	public abstract String[] getHooKMethodAnnotations();

	/**
	 * 检查Hook点类是否匹配
	 *
	 * @return
	 */
	public abstract boolean classMatcher(RASPClassDesc classDesc);

	/**
	 * 检查Hook点类是否匹配
	 *
	 * @param clazz
	 * @return
	 */
	public abstract boolean classMatcher(Class clazz);

	/**
	 * 检测Hook点方法是否匹配
	 *
	 * @param methodDesc
	 * @return
	 */
	public abstract Set<RASPHookConfig> methodMatcher(RASPMethodDesc methodDesc);

}
