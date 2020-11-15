package com.anbai.sec.vuls.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;

public class XSSFilter implements Filter {

	@Override
	public void init(FilterConfig filterConfig) {

	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;

		// 创建HttpServletRequestWrapper，包装原HttpServletRequest对象，示例程序只重写了getParameter方法，
		// 应当考虑如何过滤：getParameter、getParameterValues、getParameterMap、getInputStream、getReader
		HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(request) {
			public String getParameter(String name) {
				// 获取参数值
				String value = super.getParameter(name);

				// 简单转义参数值中的特殊字符
				return value.replace("&", "&amp;").replace("<", "&lt;").replace("'", "&#039;");
			}
		};

		chain.doFilter(requestWrapper, resp);
	}

	@Override
	public void destroy() {

	}

}
