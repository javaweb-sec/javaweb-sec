/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

public interface PartProxy {

	InputStream getInputStream() throws IOException;

	String getContentType();

	String getName();

	String getSubmittedFileName();

	long getSize();

	void write(String fileName) throws IOException;

	void delete() throws IOException;

	String getHeader(String name);

	Collection<String> getHeaders(String name);

	Collection<String> getHeaderNames();

}
