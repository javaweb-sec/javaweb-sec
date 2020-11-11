/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet;

import com.anbai.sec.rasp.servlet.http.RASPServletInputStream;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.Map;

/**
 * 定一部分需要代理的ServletRequest方法.
 *
 * @author yz
 */
public interface ServletRequestProxy {

	Object getAttribute(String name);

	void setAttribute(String name, Object o);

	String getCharacterEncoding();

	void setCharacterEncoding(String env) throws UnsupportedEncodingException;

	int getContentLength();

	String getContentType();

	RASPServletInputStream getInputStream() throws IOException;

	String getParameter(String name);

	Enumeration<String> getParameterNames();

	String[] getParameterValues(String name);

	Map<String, String[]> getParameterMap();

	String getProtocol();

	String getScheme();

	String getServerName();

	int getServerPort();

	BufferedReader getReader() throws IOException;

	String getRemoteAddr();

	String getRemoteHost();

	String getRealPath(String path);

	int getRemotePort();

	String getLocalName();

	String getLocalAddr();

	int getLocalPort();

}
