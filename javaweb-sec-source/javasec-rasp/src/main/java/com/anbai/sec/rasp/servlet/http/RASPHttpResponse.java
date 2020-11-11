/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet.http;

import com.anbai.sec.rasp.servlet.HttpServletResponseProxy;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Locale;

public class RASPHttpResponse implements HttpServletResponseProxy {

	private Object response;

	private Class responseClass;

	public RASPHttpResponse(Object response) {
		this.response = response;
		this.responseClass = response.getClass();
	}

	public Class getResponseClass() {
		return responseClass;
	}

	@Override
	public boolean containsHeader(String name) {
		try {
			Method method = responseClass.getMethod("containsHeader", String.class);
			method.setAccessible(true);

			return (Boolean) method.invoke(response, name);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public String encodeURL(String url) {
		try {
			Method method = responseClass.getMethod("encodeURL", String.class);
			method.setAccessible(true);

			return (String) method.invoke(response, url);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String encodeRedirectURL(String url) {
		try {
			Method method = responseClass.getMethod("encodeRedirectURL", String.class);
			method.setAccessible(true);

			return (String) method.invoke(response, url);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String encodeUrl(String url) {
		try {
			Method method = responseClass.getMethod("encodeUrl", String.class);
			method.setAccessible(true);

			return (String) method.invoke(response, url);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String encodeRedirectUrl(String url) {
		try {
			Method method = responseClass.getMethod("encodeRedirectUrl", String.class);
			method.setAccessible(true);

			return (String) method.invoke(response, url);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public void sendError(int sc, String msg) throws IOException {
		try {
			Method method = responseClass.getMethod("sendError", int.class, String.class);
			method.setAccessible(true);
			method.invoke(response, sc, msg);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void sendError(int sc) throws IOException {
		try {
			Method method = responseClass.getMethod("sendError", int.class);
			method.setAccessible(true);
			method.invoke(response, sc);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		try {
			Method method = responseClass.getMethod("sendRedirect", String.class);
			method.setAccessible(true);
			method.invoke(response, location);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void setDateHeader(String name, long date) {
		try {
			Method method = responseClass.getMethod("setDateHeader", String.class, long.class);
			method.setAccessible(true);
			method.invoke(response, name, date);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void addDateHeader(String name, long date) {
		try {
			Method method = responseClass.getMethod("addDateHeader", String.class, long.class);
			method.setAccessible(true);
			method.invoke(response, name, date);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void setHeader(String name, String value) {
		try {
			Method method = responseClass.getMethod("setHeader", String.class, String.class);
			method.setAccessible(true);
			method.invoke(response, name, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void addHeader(String name, String value) {
		try {
			Method method = responseClass.getMethod("addHeader", String.class, String.class);
			method.setAccessible(true);
			method.invoke(response, name, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void setIntHeader(String name, int value) {
		try {
			Method method = responseClass.getMethod("setIntHeader", String.class, int.class);
			method.setAccessible(true);
			method.invoke(response, name, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void addIntHeader(String name, int value) {
		try {
			Method method = responseClass.getMethod("addIntHeader", String.class, int.class);
			method.setAccessible(true);
			method.invoke(response, name, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void setStatus(int sc, String sm) {
		try {
			Method method = responseClass.getMethod("setStatus", int.class, String.class);
			method.setAccessible(true);
			method.invoke(response, sc, sm);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public int getStatus() {
		try {
			Method method = responseClass.getMethod("getStatus");
			method.setAccessible(true);

			return (Integer) method.invoke(response);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	@Override
	public void setStatus(int sc) {
		try {
			Method method = responseClass.getMethod("setStatus", int.class);
			method.setAccessible(true);
			method.invoke(response, sc);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public String getHeader(String name) {
		try {
			Method method = responseClass.getMethod("getHeader", String.class);
			method.setAccessible(true);

			return (String) method.invoke(response, name);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public Collection<String> getHeaders(String name) {
		try {
			Method method = responseClass.getMethod("getHeaders", String.class);
			method.setAccessible(true);

			Object obj = method.invoke(response, name);

			if (obj != null) {
				return (Collection) obj;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public Collection<String> getHeaderNames() {
		try {
			Method method = responseClass.getMethod("getHeaderNames");
			method.setAccessible(true);

			return (Collection) method.invoke(response);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public String getCharacterEncoding() {
		try {
			Method method = responseClass.getMethod("getCharacterEncoding");
			method.setAccessible(true);

			return (String) method.invoke(response);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public void setCharacterEncoding(String charset) {
		try {
			Method method = responseClass.getMethod("setCharacterEncoding", String.class);
			method.setAccessible(true);
			method.invoke(response, charset);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public String getContentType() {
		try {
			Method method = responseClass.getMethod("getContentType");
			method.setAccessible(true);

			return (String) method.invoke(response);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public void setContentType(String type) {
		try {
			Method method = responseClass.getMethod("setContentType", String.class);
			method.setAccessible(true);
			method.invoke(response, type);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public RASPServletOutputStream getOutputStream() throws IOException {
		try {
			Method method = responseClass.getMethod("getOutputStream");
			method.setAccessible(true);

			Object obj = method.invoke(response);

			if (obj != null) {
				return new RASPServletOutputStream(obj);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public PrintWriter getWriter() throws IOException {
		try {
			Method method = responseClass.getMethod("getWriter");
			method.setAccessible(true);

			Object obj = method.invoke(response);

			if (obj != null) {
				return (PrintWriter) obj;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public void setContentLength(int len) {
		try {
			Method method = responseClass.getMethod("setContentLength", int.class);
			method.setAccessible(true);
			method.invoke(response, len);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void setContentLengthLong(long len) {
		try {
			Method method = responseClass.getMethod("setContentLengthLong", long.class);
			method.setAccessible(true);
			method.invoke(response, len);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public int getBufferSize() {
		try {
			Method method = responseClass.getMethod("getBufferSize");
			method.setAccessible(true);

			return (Integer) method.invoke(response);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return -1;
	}

	@Override
	public void setBufferSize(int size) {
		try {
			Method method = responseClass.getMethod("setBufferSize", int.class);
			method.setAccessible(true);
			method.invoke(response, size);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void flushBuffer() throws IOException {
		try {
			Method method = responseClass.getMethod("flushBuffer");
			method.setAccessible(true);
			method.invoke(response);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void resetBuffer() {
		try {
			Method method = responseClass.getMethod("resetBuffer");
			method.setAccessible(true);
			method.invoke(response);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public boolean isCommitted() {
		try {
			Method method = responseClass.getMethod("isCommitted");
			method.setAccessible(true);

			return (Boolean) method.invoke(response);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public void reset() {
		try {
			Method method = responseClass.getMethod("reset");
			method.setAccessible(true);
			method.invoke(response);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public Locale getLocale() {
		try {
			Method method = responseClass.getMethod("getLocale");
			method.setAccessible(true);

			return (Locale) method.invoke(response);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public void setLocale(Locale loc) {
		try {
			Method method = responseClass.getMethod("setLocale", Locale.class);
			method.setAccessible(true);
			method.invoke(response, loc);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
