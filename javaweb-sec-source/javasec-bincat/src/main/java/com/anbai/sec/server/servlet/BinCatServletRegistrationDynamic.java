package com.anbai.sec.server.servlet;

import javax.servlet.MultipartConfigElement;
import javax.servlet.Servlet;
import javax.servlet.ServletRegistration;
import javax.servlet.ServletSecurityElement;
import java.util.*;

public class BinCatServletRegistrationDynamic implements ServletRegistration.Dynamic {

	private final String servletName;

	private final Set<String> servletMapping = new LinkedHashSet<>();

	private final Map<String, String> initParametersMap = new HashMap<>();

	private final Servlet servlet;

	private final BinCatServletContext servletContext;

	public BinCatServletRegistrationDynamic(String servletName, Servlet servlet, BinCatServletContext servletContext) {
		this.servletName = servletName;
		this.servlet = servlet;
		this.servletContext = servletContext;
	}

	@Override
	public void setLoadOnStartup(int loadOnStartup) {

	}

	@Override
	public Set<String> setServletSecurity(ServletSecurityElement constraint) {
		return null;
	}

	@Override
	public void setMultipartConfig(MultipartConfigElement multipartConfig) {

	}

	@Override
	public void setRunAsRole(String roleName) {

	}

	@Override
	public void setAsyncSupported(boolean isAsyncSupported) {

	}

	@Override
	public Set<String> addMapping(String... urlPatterns) {
		Collections.addAll(servletMapping, urlPatterns);

		return servletMapping;
	}

	@Override
	public Collection<String> getMappings() {
		return servletMapping;
	}

	@Override
	public String getRunAsRole() {
		return null;
	}

	@Override
	public String getName() {
		return servletName;
	}

	@Override
	public String getClassName() {
		return servlet.getClass().getName();
	}

	@Override
	public boolean setInitParameter(String name, String value) {
		if (!initParametersMap.containsKey(name)) {
			initParametersMap.put(name, value);

			return true;
		}

		return false;
	}

	@Override
	public String getInitParameter(String name) {
		return initParametersMap.get(name);
	}

	@Override
	public Set<String> setInitParameters(Map<String, String> initParameters) {
		initParametersMap.putAll(initParameters);

		return initParametersMap.keySet();
	}

	@Override
	public Map<String, String> getInitParameters() {
		return initParametersMap;
	}

	public Servlet getServlet() {
		return servlet;
	}

	public String getServletName() {
		return servletName;
	}

}
