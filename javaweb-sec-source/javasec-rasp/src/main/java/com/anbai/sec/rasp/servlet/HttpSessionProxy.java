/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet;

import com.anbai.sec.rasp.servlet.http.RASPServletContext;

import java.util.Enumeration;

public interface HttpSessionProxy {

	long getCreationTime();

	String getId();

	long getLastAccessedTime();

	RASPServletContext getServletContext();

	int getMaxInactiveInterval();

	void setMaxInactiveInterval(int interval);

	Object getAttribute(String name);

	Object getValue(String name);

	Enumeration<String> getAttributeNames();

	String[] getValueNames();

	void setAttribute(String name, Object value);

	void putValue(String name, Object value);

	void removeAttribute(String name);

	void removeValue(String name);

	void invalidate();

	boolean isNew();

}

