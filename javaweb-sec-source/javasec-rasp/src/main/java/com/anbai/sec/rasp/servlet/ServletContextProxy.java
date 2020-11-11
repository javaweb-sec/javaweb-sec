/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet;

import com.anbai.sec.rasp.servlet.http.RASPServletContext;

import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;
import java.util.Set;

public interface ServletContextProxy {

	String getContextPath();

	RASPServletContext getContext(String uriPath);

	int getMajorVersion();

	int getMinorVersion();

	int getEffectiveMajorVersion();

	int getEffectiveMinorVersion();

	String getMimeType(String file);

	Set<String> getResourcePaths(String path);

	URL getResource(String path) throws MalformedURLException;

	InputStream getResourceAsStream(String path);

	Enumeration<String> getServletNames();

	String getRealPath(String path);

	String getServerInfo();

	String getInitParameter(String name);

	Enumeration<String> getInitParameterNames();

	boolean setInitParameter(String name, String value);

	Object getAttribute(String name);

	Enumeration<String> getAttributeNames();

	void setAttribute(String name, Object object);

	void removeAttribute(String name);

	String getServletContextName();

	ClassLoader getClassLoader();

	String getVirtualServerName();

}
