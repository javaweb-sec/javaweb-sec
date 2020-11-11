/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet.http;

import com.anbai.sec.rasp.servlet.HttpSessionProxy;

import java.lang.reflect.Method;
import java.util.Enumeration;

public class RASPHttpSession implements HttpSessionProxy {

	private Object session;

	private Class sessionClass;

	public RASPHttpSession(Object session) {
		this.session = session;
		this.sessionClass = this.session.getClass();

	}

	public Class getSessionClass() {
		return sessionClass;
	}

	@Override
	public long getCreationTime() {
		try {
			Method method = sessionClass.getMethod("getCreationTime");
			method.setAccessible(true);
			return (Long) method.invoke(session);
		} catch (Exception e) {
			e.printStackTrace();
			return -1L;
		}
	}

	@Override
	public String getId() {
		try {
			Method method = sessionClass.getMethod("getId");
			method.setAccessible(true);
			return (String) method.invoke(session);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public long getLastAccessedTime() {
		try {
			Method method = sessionClass.getMethod("getLastAccessedTime");
			method.setAccessible(true);
			return (Long) method.invoke(session);
		} catch (Exception e) {
			e.printStackTrace();
			return -1L;
		}
	}

	@Override
	public RASPServletContext getServletContext() {
		try {
			Method method = sessionClass.getMethod("getServletContext");
			method.setAccessible(true);
			Object context = method.invoke(session);

			return new RASPServletContext(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public int getMaxInactiveInterval() {
		try {
			Method method = sessionClass.getMethod("getMaxInactiveInterval");
			method.setAccessible(true);
			return (Integer) method.invoke(session);
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
	}

	@Override
	public void setMaxInactiveInterval(int interval) {
		try {
			Method method = sessionClass.getMethod("setMaxInactiveInterval", int.class);
			method.setAccessible(true);
			method.invoke(session, interval);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public Object getAttribute(String name) {
		try {
			Method method = sessionClass.getMethod("getAttribute", String.class);
			method.setAccessible(true);
			return method.invoke(session, name);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Object getValue(String name) {
		try {
			Method method = sessionClass.getMethod("getValue", String.class);
			method.setAccessible(true);
			return method.invoke(session, name);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Enumeration<String> getAttributeNames() {
		try {
			Method method = sessionClass.getMethod("getAttributeNames");
			method.setAccessible(true);
			return (Enumeration) method.invoke(session);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String[] getValueNames() {
		try {
			Method method = sessionClass.getMethod("getValueNames");
			method.setAccessible(true);
			return (String[]) method.invoke(session);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public void setAttribute(String name, Object value) {
		try {
			Method method = sessionClass.getMethod("setAttribute", String.class, Object.class);
			method.setAccessible(true);
			method.invoke(session, name, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void putValue(String name, Object value) {
		try {
			Method method = sessionClass.getMethod("putValue", String.class, Object.class);
			method.setAccessible(true);
			method.invoke(session, name, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void removeAttribute(String name) {
		try {
			Method method = sessionClass.getMethod("removeAttribute", String.class);
			method.setAccessible(true);
			method.invoke(session, name);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void removeValue(String name) {
		try {
			Method method = sessionClass.getMethod("removeValue", String.class);
			method.setAccessible(true);
			method.invoke(session, name);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void invalidate() {
		try {
			Method method = sessionClass.getMethod("invalidate");
			method.setAccessible(true);
			method.invoke(session);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public boolean isNew() {
		try {
			Method method = sessionClass.getMethod("isNew");
			method.setAccessible(true);
			return (Boolean) method.invoke(session);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

}
