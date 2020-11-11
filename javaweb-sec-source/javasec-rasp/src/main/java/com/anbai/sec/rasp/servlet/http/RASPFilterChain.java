/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet.http;

import com.anbai.sec.rasp.servlet.FilterChainProxy;

import java.io.IOException;
import java.lang.reflect.Method;

public class RASPFilterChain implements FilterChainProxy {

	private Object chain;

	private Class chainClass;

	public RASPFilterChain(Object chain) {
		this.chain = chain;
		this.chainClass = this.chain.getClass();
	}

	public Class getChainClass() {
		return chainClass;
	}

	@Override
	public void doFilter(Object request, Object response) throws IOException {

		try {
			Method method = chainClass.getMethod("doFilter", request.getClass(), response.getClass());
			method.setAccessible(true);
			method.invoke(chain);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
