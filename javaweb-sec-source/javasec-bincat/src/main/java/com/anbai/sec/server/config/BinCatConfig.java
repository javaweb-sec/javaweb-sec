package com.anbai.sec.server.config;

import com.anbai.sec.server.servlet.BinCatServletContext;
import com.anbai.sec.server.test.servlet.CMDServlet;
import com.anbai.sec.server.test.servlet.IndexServlet;
import com.anbai.sec.server.test.servlet.QuercusPHPServlet;
import com.anbai.sec.server.test.servlet.TestServlet;

import javax.servlet.Servlet;
import java.util.HashSet;
import java.util.Set;

public class BinCatConfig {

	// 初始化Servlet映射类对象
	private static final Set<Class<? extends Servlet>> SERVLET_LIST = new HashSet<>();

	/**
	 * 手动注册Servlet并创建BinCatServletContext对象
	 *
	 * @return ServletContext
	 */
	public static BinCatServletContext createServletContext() throws Exception {
		// 手动注册Servlet类
		SERVLET_LIST.add(IndexServlet.class);
		SERVLET_LIST.add(TestServlet.class);
		SERVLET_LIST.add(CMDServlet.class);
		SERVLET_LIST.add(QuercusPHPServlet.class);

		// 创建ServletContext
		return new BinCatServletContext(SERVLET_LIST);
	}

}
