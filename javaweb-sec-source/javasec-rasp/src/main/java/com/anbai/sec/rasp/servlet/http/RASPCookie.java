/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet.http;

import java.lang.reflect.Method;

public class RASPCookie {

	private Object cookie;

	private Class cookieClass;

	public RASPCookie(Object cookie) {
		this.cookie = cookie;
		this.cookieClass = this.cookie.getClass();
	}

	public RASPCookie(Class clazz, String name, String value) {
		this.cookieClass = clazz;

		try {
			this.cookie = cookieClass.getConstructor(String.class, String.class).newInstance(name, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public Class getCookieClass() {
		return cookieClass;
	}

	public String getComment() {
		try {
			Method method = cookieClass.getMethod("getComment");
			method.setAccessible(true);
			return (String) method.invoke(cookie);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public void setComment(String purpose) {
		try {
			Method method = cookieClass.getMethod("setComment", String.class);
			method.setAccessible(true);
			method.invoke(cookie, purpose);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public String getDomain() {
		try {
			Method method = cookieClass.getMethod("getDomain");
			method.setAccessible(true);
			return (String) method.invoke(cookie);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public void setDomain(String domain) {
		try {
			Method method = cookieClass.getMethod("setDomain", String.class);
			method.setAccessible(true);
			method.invoke(cookie, domain);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public int getMaxAge() {
		try {
			Method method = cookieClass.getMethod("getMaxAge");
			method.setAccessible(true);
			return (Integer) method.invoke(cookie);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	public void setMaxAge(int expiry) {
		try {
			Method method = cookieClass.getMethod("setMaxAge", int.class);
			method.setAccessible(true);
			method.invoke(cookie, expiry);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public String getPath() {
		try {
			Method method = cookieClass.getMethod("getPath");
			method.setAccessible(true);
			return (String) method.invoke(cookie);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public void setPath(String uri) {
		try {
			Method method = cookieClass.getMethod("setPath", String.class);
			method.setAccessible(true);
			method.invoke(cookie, uri);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public boolean getSecure() {
		try {
			Method method = cookieClass.getMethod("getSecure");
			method.setAccessible(true);
			return (Boolean) method.invoke(cookie);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	public void setSecure(boolean flag) {
		try {
			Method method = cookieClass.getMethod("setSecure", boolean.class);
			method.setAccessible(true);
			method.invoke(cookie, flag);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public String getName() {
		try {
			Method method = cookieClass.getMethod("getName");
			method.setAccessible(true);
			return (String) method.invoke(cookie);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public String getValue() {
		try {
			Method method = cookieClass.getMethod("getValue");
			method.setAccessible(true);
			return (String) method.invoke(cookie);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public void setValue(String newValue) {
		try {
			Method method = cookieClass.getMethod("setValue", String.class);
			method.setAccessible(true);
			method.invoke(cookie, newValue);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public int getVersion() {
		try {
			Method method = cookieClass.getMethod("getVersion");
			method.setAccessible(true);
			return (Integer) method.invoke(cookie);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	public void setVersion(int v) {
		try {
			Method method = cookieClass.getMethod("setVersion", int.class);
			method.setAccessible(true);
			method.invoke(cookie, v);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public boolean isHttpOnly() {
		try {
			Method method = cookieClass.getMethod("isHttpOnly");
			method.setAccessible(true);
			return (Boolean) method.invoke(cookie);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	public void setHttpOnly(boolean isHttpOnly) {
		try {
			Method method = cookieClass.getMethod("setHttpOnly", boolean.class);
			method.setAccessible(true);
			method.invoke(cookie, isHttpOnly);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
