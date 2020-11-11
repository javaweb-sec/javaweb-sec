/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet.http;

import java.io.IOException;
import java.lang.reflect.Method;

public class RASPServletOutputStream {

	private Object servletOutputStream;

	private Class servletOutputStreamClass;

	public RASPServletOutputStream(Object servletOutputStream) {
		this.servletOutputStream = servletOutputStream;
		this.servletOutputStreamClass = servletOutputStream.getClass();
	}

	public Class getServletOutputStreamClass() {
		return servletOutputStreamClass;
	}

	public void print(String s) throws IOException {
		try {
			Method method = servletOutputStreamClass.getMethod("print", String.class);
			method.setAccessible(true);
			method.invoke(servletOutputStream, s);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void println(String s) throws IOException {
		try {
			Method method = servletOutputStreamClass.getMethod("println", String.class);
			method.setAccessible(true);
			method.invoke(servletOutputStream, s);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void write(int b) throws IOException {
		try {
			Method method = servletOutputStreamClass.getMethod("write", int.class);
			method.setAccessible(true);
			method.invoke(servletOutputStream, b);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void write(byte b[]) throws IOException {
		try {
			Method method = servletOutputStreamClass.getMethod("write", byte[].class);
			method.setAccessible(true);
			method.invoke(servletOutputStream, b);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void write(byte b[], int off, int len) throws IOException {
		try {
			Method method = servletOutputStreamClass.getMethod("write", byte[].class, int.class, int.class);
			method.setAccessible(true);
			method.invoke(servletOutputStream, b, off, len);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
