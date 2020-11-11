/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet.http;

import com.anbai.sec.rasp.servlet.HttpServletRequestProxy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.util.Enumeration;
import java.util.Map;

public class RASPHttpRequest implements HttpServletRequestProxy {

	private Object request;

	private Class requestClass;

	public RASPHttpRequest(Object request) {
		this.request = request;
		this.requestClass = request.getClass();
	}

	public Class getRequestClass() {
		return requestClass;
	}

	@Override
	public RASPHttpSession getSession(boolean create) {
		try {
			Method method = requestClass.getMethod("getSession", boolean.class);
			method.setAccessible(true);
			Object obj = method.invoke(request, create);

			if (obj != null) {
				return new RASPHttpSession(obj);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public RASPHttpSession getSession() {
		try {
			Method method = requestClass.getMethod("getSession");
			method.setAccessible(true);
			Object obj = method.invoke(request);

			if (obj != null) {
				return new RASPHttpSession(obj);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public RASPCookie[] getCookies() {
		try {
			Method method = requestClass.getMethod("getCookies");
			method.setAccessible(true);
			Object[] obj = (Object[]) method.invoke(request);

			if (obj != null) {
				RASPCookie[] cookies = new RASPCookie[obj.length];

				for (int i = 0; i < obj.length; i++) {
					cookies[i] = new RASPCookie(obj[i]);
				}

				return cookies;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getHeader(String name) {
		try {
			Method method = requestClass.getMethod("getHeader", String.class);
			method.setAccessible(true);

			return (String) method.invoke(request, name);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Enumeration<String> getHeaders(String name) {
		try {
			Method method = requestClass.getMethod("getHeaders", String.class);
			method.setAccessible(true);

			Object headers = method.invoke(request, name);

			if (headers != null) {
				return (Enumeration) headers;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Enumeration<String> getHeaderNames() {
		try {
			Method method = requestClass.getMethod("getHeaderNames");
			method.setAccessible(true);

			Object headerNames = method.invoke(request);

			if (headerNames != null) {
				return (Enumeration) headerNames;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getMethod() {
		try {
			Method method = requestClass.getMethod("getMethod");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getContextPath() {
		try {
			Method method = requestClass.getMethod("getContextPath");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getQueryString() {
		try {
			Method method = requestClass.getMethod("getQueryString");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getRequestedSessionId() {
		try {
			Method method = requestClass.getMethod("getRequestedSessionId");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getRequestURI() {
		try {
			Method method = requestClass.getMethod("getRequestURI");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public StringBuffer getRequestURL() {
		try {
			Method method = requestClass.getMethod("getRequestURL");
			method.setAccessible(true);

			return (StringBuffer) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getServletPath() {
		try {
			Method method = requestClass.getMethod("getServletPath");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}


	@Override
	public Object getAttribute(String name) {
		try {
			Method method = requestClass.getMethod("getAttribute", String.class);
			method.setAccessible(true);

			return method.invoke(request, name);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public void setAttribute(String name, Object o) {
		try {
			Method method = requestClass.getMethod("setAttribute", String.class, Object.class);
			method.setAccessible(true);

			method.invoke(request, name, o);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public String getCharacterEncoding() {
		try {
			Method method = requestClass.getMethod("getCharacterEncoding");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public void setCharacterEncoding(String env) throws UnsupportedEncodingException {
		try {
			Method method = requestClass.getMethod("setCharacterEncoding", String.class);
			method.setAccessible(true);
			method.invoke(request, env);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public int getContentLength() {
		try {
			Method method = requestClass.getMethod("getContentLength");
			method.setAccessible(true);

			return (Integer) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
	}

	@Override
	public String getContentType() {
		try {
			Method method = requestClass.getMethod("getContentType");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public RASPServletInputStream getInputStream() throws IOException {
		try {
			Method method = requestClass.getMethod("getInputStream");
			method.setAccessible(true);

			Object inputStream = method.invoke(request);

			if (inputStream != null) {
				return new RASPServletInputStream(inputStream);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getParameter(String name) {
		try {
			Method method = requestClass.getMethod("getParameter", String.class);
			method.setAccessible(true);

			return (String) method.invoke(request, name);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Enumeration<String> getParameterNames() {
		try {
			Method method = requestClass.getMethod("getParameterNames");
			method.setAccessible(true);

			return (Enumeration) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String[] getParameterValues(String name) {
		try {
			Method method = requestClass.getMethod("getParameterValues", String.class);
			method.setAccessible(true);

			Object values = method.invoke(request, name);

			if (values != null) {
				return (String[]) values;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Map<String, String[]> getParameterMap() {
		try {
			Method method = requestClass.getMethod("getParameterMap");
			method.setAccessible(true);

			Object map = method.invoke(request);

			if (map != null) {
				return (Map) map;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getProtocol() {
		try {
			Method method = requestClass.getMethod("getProtocol");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getScheme() {
		try {
			Method method = requestClass.getMethod("getScheme");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getServerName() {
		try {
			Method method = requestClass.getMethod("getServerName");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public int getServerPort() {
		try {
			Method method = requestClass.getMethod("getServerPort");
			method.setAccessible(true);

			return (Integer) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	@Override
	public BufferedReader getReader() throws IOException {
		try {
			Method method = requestClass.getMethod("getReader");
			method.setAccessible(true);

			Object reader = method.invoke(request);

			if (reader != null) {
				return (BufferedReader) reader;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getRemoteAddr() {
		try {
			Method method = requestClass.getMethod("getRemoteAddr");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getRemoteHost() {
		try {
			Method method = requestClass.getMethod("getRemoteHost");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getRealPath(String path) {
		try {
			Method method = requestClass.getMethod("getRealPath", String.class);
			method.setAccessible(true);

			return (String) method.invoke(request, path);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public int getRemotePort() {
		try {
			Method method = requestClass.getMethod("getRemotePort");
			method.setAccessible(true);
			return (Integer) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
	}

	@Override
	public String getLocalName() {
		try {
			Method method = requestClass.getMethod("getLocalName");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getLocalAddr() {
		try {
			Method method = requestClass.getMethod("getLocalAddr");
			method.setAccessible(true);

			return (String) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public int getLocalPort() {
		try {
			Method method = requestClass.getMethod("getLocalPort");
			method.setAccessible(true);

			return (Integer) method.invoke(request);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return 0;
	}

}
