/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet.http;

import com.anbai.sec.rasp.servlet.PartProxy;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Collection;

public class RASPPart implements PartProxy {

	private Object part;

	private Class partClass;

	public RASPPart(Object part) {
		this.part = part;
		this.partClass = part.getClass();
	}

	public Class getPartClass() {
		return partClass;
	}

	@Override
	public InputStream getInputStream() throws IOException {
		try {
			Method method = partClass.getMethod("getInputStream");
			method.setAccessible(true);

			Object in = method.invoke(part);

			if (in != null) {
				return (InputStream) method.invoke(part);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getContentType() {
		try {
			Method method = partClass.getMethod("getContentType");
			method.setAccessible(true);

			return (String) method.invoke(part);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getName() {
		try {
			Method method = partClass.getMethod("getName");
			method.setAccessible(true);

			return (String) method.invoke(part);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getSubmittedFileName() {
		try {
			Method method = partClass.getMethod("getSubmittedFileName");
			method.setAccessible(true);

			return (String) method.invoke(part);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public long getSize() {
		try {
			Method method = partClass.getMethod("getSize");
			method.setAccessible(true);

			return (Long) method.invoke(part);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return 0;
	}

	@Override
	public void write(String fileName) throws IOException {
		try {
			Method method = partClass.getMethod("write", String.class);
			method.setAccessible(true);
			method.invoke(part, fileName);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void delete() throws IOException {
		try {
			Method method = partClass.getMethod("delete");
			method.setAccessible(true);
			method.invoke(part);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public String getHeader(String name) {
		try {
			Method method = partClass.getMethod("getHeader", String.class);
			method.setAccessible(true);

			return (String) method.invoke(part, name);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Collection<String> getHeaders(String name) {
		try {
			Method method = partClass.getMethod("getHeaders", String.class);
			method.setAccessible(true);

			Object objs = method.invoke(part, name);

			if (objs != null) {
				return (Collection<String>) objs;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Collection<String> getHeaderNames() {
		try {
			Method method = partClass.getMethod("getHeaderNames");
			method.setAccessible(true);

			Object objs = method.invoke(part);

			if (objs != null) {
				return (Collection<String>) objs;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

}
