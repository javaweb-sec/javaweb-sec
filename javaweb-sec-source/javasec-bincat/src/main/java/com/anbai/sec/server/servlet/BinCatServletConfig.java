package com.anbai.sec.server.servlet;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public class BinCatServletConfig implements ServletConfig {

	private final BinCatServletContext servletContext;

	private final WebServlet webServlet;

	private final WebInitParam[] webInitParam;

	public BinCatServletConfig(BinCatServletContext servletContext, WebServlet webServlet) {
		this.servletContext = servletContext;
		this.webServlet = webServlet;
		this.webInitParam = webServlet.initParams();
	}

	@Override
	public String getServletName() {
		return webServlet.name();
	}

	@Override
	public ServletContext getServletContext() {
		return this.servletContext;
	}

	@Override
	public String getInitParameter(String name) {
		for (WebInitParam initParam : webInitParam) {
			String paramName = initParam.name();

			if (paramName.equals(name)) {
				return initParam.value();
			}
		}

		return null;
	}

	@Override
	public Enumeration<String> getInitParameterNames() {
		Set<String> initParamSet = new HashSet<String>();

		for (WebInitParam initParam : webInitParam) {
			initParamSet.add(initParam.name());
		}

		return Collections.enumeration(initParamSet);
	}

}
