package com.anbai.sec.server.servlet;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionContext;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * BinCat Session实现
 */
public class BinCatSession implements HttpSession {

	private final String sessionID;

	// Http请求Session对象
	private final Map<String, Object> sessionMap = new ConcurrentHashMap<String, Object>();

	public BinCatSession(String sessionID) {
		this.sessionID = sessionID;
	}

	public long getCreationTime() {
		return 0;
	}

	public String getId() {
		return sessionID;
	}

	public long getLastAccessedTime() {
		return 0;
	}

	public ServletContext getServletContext() {
		return null;
	}

	public void setMaxInactiveInterval(int interval) {

	}

	public int getMaxInactiveInterval() {
		return 0;
	}

	public HttpSessionContext getSessionContext() {
		return null;
	}

	public Object getAttribute(String name) {
		return this.sessionMap.get(name);
	}

	public Object getValue(String name) {
		return this.sessionMap.get(name);
	}

	public Enumeration<String> getAttributeNames() {
		return null;
	}

	public String[] getValueNames() {
		return new String[0];
	}

	public void setAttribute(String name, Object value) {
		this.sessionMap.put(name, value);
	}

	public void putValue(String name, Object value) {
		this.sessionMap.put(name, value);
	}

	public void removeAttribute(String name) {
		this.sessionMap.remove(name);
	}

	public void removeValue(String name) {
		this.sessionMap.remove(name);
	}

	public void invalidate() {

	}

	public boolean isNew() {
		return false;
	}

}
