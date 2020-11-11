/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet;

import com.anbai.sec.rasp.servlet.http.RASPServletOutputStream;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;

public interface ServletResponseProxy {

	String getCharacterEncoding();

	void setCharacterEncoding(String charset);

	String getContentType();

	void setContentType(String type);

	RASPServletOutputStream getOutputStream() throws IOException;

	PrintWriter getWriter() throws IOException;

	void setContentLength(int len);

	void setContentLengthLong(long len);

	int getBufferSize();

	void setBufferSize(int size);

	void flushBuffer() throws IOException;

	void resetBuffer();

	boolean isCommitted();

	void reset();

	Locale getLocale();

	void setLocale(Locale loc);

}