/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet;

import com.anbai.sec.rasp.servlet.http.RASPCookie;
import com.anbai.sec.rasp.servlet.http.RASPHttpSession;

import java.util.Enumeration;

/**
 * 定一部分需要代理的HttpServletRequest方法.
 *
 * @author yz
 */
public interface HttpServletRequestProxy extends ServletRequestProxy {

	RASPHttpSession getSession(boolean create);

	RASPHttpSession getSession();

	RASPCookie[] getCookies();

	String getHeader(String name) throws NoSuchMethodException;

	Enumeration<String> getHeaders(String name);

	Enumeration<String> getHeaderNames();

	String getMethod();

	String getContextPath();

	String getQueryString();

	String getRequestedSessionId();

	String getRequestURI();

	StringBuffer getRequestURL();

	String getServletPath();

}
