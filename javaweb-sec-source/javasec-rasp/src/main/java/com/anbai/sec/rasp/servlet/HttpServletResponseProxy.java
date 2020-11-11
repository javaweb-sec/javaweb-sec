/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet;

import java.io.IOException;
import java.util.Collection;

public interface HttpServletResponseProxy extends ServletResponseProxy {

	boolean containsHeader(String name);

	String encodeURL(String url);

	String encodeRedirectURL(String url);

	String encodeUrl(String url);

	String encodeRedirectUrl(String url);

	void sendError(int sc, String msg) throws IOException;

	void sendError(int sc) throws IOException;

	void sendRedirect(String location) throws IOException;

	void setDateHeader(String name, long date);

	void addDateHeader(String name, long date);

	void setHeader(String name, String value);

	void addHeader(String name, String value);

	void setIntHeader(String name, int value);

	void addIntHeader(String name, int value);

	void setStatus(int sc, String sm);

	int getStatus();

	void setStatus(int sc);

	String getHeader(String name);

	Collection<String> getHeaders(String name);

	Collection<String> getHeaderNames();

}
