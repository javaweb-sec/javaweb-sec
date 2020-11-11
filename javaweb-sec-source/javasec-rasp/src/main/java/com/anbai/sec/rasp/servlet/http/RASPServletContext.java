/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet.http;

import com.anbai.sec.rasp.servlet.ServletContextProxy;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;
import java.util.Set;

public class RASPServletContext implements ServletContextProxy {

	private Object context;

	private Class contextClass;

	public RASPServletContext(Object servletContext) {
		this.context = servletContext;
		this.contextClass = this.context.getClass();
	}

	public Class getContextClass() {
		return contextClass;
	}

	@Override
	public String getContextPath() {
		try {
			Method method = contextClass.getMethod("getContextPath");
			method.setAccessible(true);
			return (String) method.invoke(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public RASPServletContext getContext(String uriPath) {
		try {
			Method method = contextClass.getMethod("getContext", String.class);
			method.setAccessible(true);
			Object obj = method.invoke(context, uriPath);

			if (obj != null) {
				return new RASPServletContext(obj);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public int getMajorVersion() {
		try {
			Method method = contextClass.getMethod("getMajorVersion");
			method.setAccessible(true);
			return (Integer) method.invoke(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	@Override
	public int getMinorVersion() {
		try {
			Method method = contextClass.getMethod("getMinorVersion");
			method.setAccessible(true);
			return (Integer) method.invoke(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	@Override
	public int getEffectiveMajorVersion() {
		try {
			Method method = contextClass.getMethod("getEffectiveMajorVersion");
			method.setAccessible(true);
			return (Integer) method.invoke(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	@Override
	public int getEffectiveMinorVersion() {
		try {
			Method method = contextClass.getMethod("getEffectiveMinorVersion");
			method.setAccessible(true);
			return (Integer) method.invoke(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	@Override
	public String getMimeType(String file) {
		try {
			Method method = contextClass.getMethod("getMimeType", String.class);
			method.setAccessible(true);
			return (String) method.invoke(context, file);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Set<String> getResourcePaths(String path) {
		try {
			Method method = contextClass.getMethod("getResourcePaths", String.class);
			method.setAccessible(true);
			return (Set) method.invoke(context, path);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public URL getResource(String path) throws MalformedURLException {
		try {
			Method method = contextClass.getMethod("getResource", String.class);
			method.setAccessible(true);

			Object url = method.invoke(context, path);

			if (url != null) {
				return (URL) url;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public InputStream getResourceAsStream(String path) {
		try {
			Method method = contextClass.getMethod("getResourceAsStream", String.class);
			method.setAccessible(true);

			Object obj = method.invoke(context, path);

			if (obj != null) {
				return (InputStream) obj;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Enumeration<String> getServletNames() {
		try {
			Method method = contextClass.getMethod("getServletNames", String.class);
			method.setAccessible(true);

			Object obj = method.invoke(context);

			if (obj != null) {
				return (Enumeration<String>) obj;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getRealPath(String path) {
		try {
			Method method = contextClass.getMethod("getRealPath", String.class);
			method.setAccessible(true);
			return (String) method.invoke(context, path);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getServerInfo() {
		try {
			Method method = contextClass.getMethod("getServerInfo");
			method.setAccessible(true);

			return (String) method.invoke(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getInitParameter(String name) {
		try {
			Method method = contextClass.getMethod("getInitParameter", String.class);
			method.setAccessible(true);

			return (String) method.invoke(context, name);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Enumeration<String> getInitParameterNames() {
		try {
			Method method = contextClass.getMethod("getInitParameterNames");
			method.setAccessible(true);

			return (Enumeration) method.invoke(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public boolean setInitParameter(String name, String value) {
		try {
			Method method = contextClass.getMethod("setInitParameter", String.class, String.class);
			method.setAccessible(true);

			return (Boolean) method.invoke(context, name, value);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public Object getAttribute(String name) {
		try {
			Method method = contextClass.getMethod("getAttribute", String.class);
			method.setAccessible(true);

			return method.invoke(context, name);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Enumeration<String> getAttributeNames() {
		try {
			Method method = contextClass.getMethod("getAttributeNames");
			method.setAccessible(true);

			Object obj = method.invoke(context);

			if (obj != null) {
				return (Enumeration<String>) obj;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public void setAttribute(String name, Object object) {
		try {
			Method method = contextClass.getMethod("setAttribute", String.class, Object.class);
			method.setAccessible(true);
			method.invoke(context, name, object);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void removeAttribute(String name) {
		try {
			Method method = contextClass.getMethod("removeAttribute", String.class);
			method.setAccessible(true);
			method.invoke(context, name);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public String getServletContextName() {
		try {
			Method method = contextClass.getMethod("getServletContextName");
			method.setAccessible(true);
			return (String) method.invoke(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public ClassLoader getClassLoader() {
		try {
			Method method = contextClass.getMethod("getClassLoader");
			method.setAccessible(true);
			return (ClassLoader) method.invoke(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getVirtualServerName() {
		try {
			Method method = contextClass.getMethod("getVirtualServerName");
			method.setAccessible(true);
			return (String) method.invoke(context);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

}
