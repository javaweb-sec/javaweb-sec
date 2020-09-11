package com.anbai.sec.server.handler;

import com.anbai.sec.server.servlet.BinCatRequest;
import com.anbai.sec.server.servlet.BinCatResponse;
import org.javaweb.utils.FileUtils;
import org.javaweb.utils.StringUtils;

import javax.servlet.Servlet;
import javax.servlet.ServletContext;
import javax.servlet.annotation.WebServlet;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.regex.Pattern;

public class BinCatDispatcherServlet {

	public void doDispatch(BinCatRequest req, BinCatResponse resp, ByteArrayOutputStream out) throws IOException {
		// 请求URI地址
		String uri = req.getRequestURI();

		// 获取ServletContext
		ServletContext servletContext = req.getServletContext();

		// 获取Http请求的文件
		File requestFile = new File(req.getRealPath(uri));

		// 处理Http请求的静态文件，如果文件存在(.php后缀除外)就直接返回文件内容，不需要调用Servlet
		if (requestFile.exists() && !uri.endsWith(".php")) {
			// 修改状态码
			resp.setStatus(200, "OK");

			// 解析文件的MimeType
			String mimeType = Files.probeContentType(requestFile.toPath());

			if (mimeType == null) {
				String fileSuffix = FileUtils.getFileSuffix(requestFile.getName());
				resp.setContentType("text/" + fileSuffix);
			} else {
				resp.setContentType(mimeType);
			}

			out.write(Files.readAllBytes(requestFile.toPath()));
		} else {
			// 遍历所有已注册得Servlet，处理Http请求
			Enumeration<Servlet> servlets = servletContext.getServlets();

			while (servlets.hasMoreElements()) {
				Servlet    servlet     = servlets.nextElement();
				WebServlet webServlet  = servlet.getClass().getAnnotation(WebServlet.class);
				String[]   urlPatterns = webServlet.urlPatterns();

				for (String urlPattern : urlPatterns) {
					try {
						// 检测请求的URL地址和Servlet的地址是否匹配
						if (Pattern.compile(urlPattern).matcher(uri).find()) {
							// 修改状态码
							resp.setStatus(200, "OK");

							// 调用Servlet请求处理方法
							servlet.service(req, resp);
							return;
						}
					} catch (Exception e) {
						// 修改状态码,输出服务器异常信息到浏览器
						resp.setStatus(500, "Internal Server Error");
						e.printStackTrace();

						out.write(("<pre>" + StringUtils.exceptionToString(e) + "</pre>").getBytes());
					}
				}
			}
		}
	}

}