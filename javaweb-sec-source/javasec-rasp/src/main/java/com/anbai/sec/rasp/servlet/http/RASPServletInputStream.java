/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet.http;

import java.io.IOException;
import java.lang.reflect.Method;

public class RASPServletInputStream {

	private Object servletInputStream;

	private Class servletInputStreamClass;

	public RASPServletInputStream(Object servletInputStream) {
		this.servletInputStream = servletInputStream;
		this.servletInputStreamClass = servletInputStream.getClass();
	}

	public Class getServletInputStreamClass() {
		return servletInputStreamClass;
	}

	public int read() throws IOException {
		try {
			Method method = servletInputStreamClass.getMethod("read");
			method.setAccessible(true);
			return (Integer) method.invoke(servletInputStream);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	public int read(byte b[]) throws IOException {
		try {
			Method method = servletInputStreamClass.getMethod("read", byte[].class);
			method.setAccessible(true);
			return (Integer) method.invoke(servletInputStream, b);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	public int read(byte b[], int off, int len) throws IOException {
		try {
			Method method = servletInputStreamClass.getMethod("read", byte[].class, int.class, int.class);
			method.setAccessible(true);
			return (Integer) method.invoke(servletInputStream, b, off, len);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	public int readLine(byte[] b, int off, int len) throws IOException {
		try {
			Method method = servletInputStreamClass.getMethod("readLine", byte[].class, int.class, int.class);
			method.setAccessible(true);
			return (Integer) method.invoke(servletInputStream, b, off, len);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	public boolean isFinished() {
		try {
			Method method = servletInputStreamClass.getMethod("isFinished");
			method.setAccessible(true);
			return (Boolean) method.invoke(servletInputStream);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	public boolean isReady() {
		try {
			Method method = servletInputStreamClass.getMethod("isReady");
			method.setAccessible(true);
			return (Boolean) method.invoke(servletInputStream);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

}
