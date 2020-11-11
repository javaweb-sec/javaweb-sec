/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.servlet;

import java.io.IOException;

public interface FilterChainProxy {

	void doFilter(Object request, Object response) throws IOException;

}