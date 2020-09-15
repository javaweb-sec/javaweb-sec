package com.anbai.sec.server.servlet;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;

public class BinCatServletConfig implements ServletConfig {

	private final BinCatServletContext servletContext;

	private final Map<String, String> initParameterMap;

	private final String servletName;

	public BinCatServletConfig(BinCatServletContext servletContext, String servletName, Map<String, String> initParameterMap) {
		this.servletContext = servletContext;
		this.initParameterMap = initParameterMap;
		this.servletName = servletName;
	}

	@Override
	public String getServletName() {
		return servletName;
	}

	@Override
	public ServletContext getServletContext() {
		return this.servletContext;
	}

	@Override
	public String getInitParameter(String name) {
		return initParameterMap.get(name);
	}

	@Override
	public Enumeration<String> getInitParameterNames() {
		return Collections.enumeration(initParameterMap.keySet());
	}

}
