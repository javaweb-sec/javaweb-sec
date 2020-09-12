package com.anbai.sec.server.test.servlet;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

@WebServlet(name = "IndexServlet", urlPatterns = {"^(\\\\|/)+$", "^(/|\\\\)+index\\.(htm|asp|jsp|do|action)"})
public class IndexServlet extends HttpServlet {

	@Override
	public void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
		OutputStream out = response.getOutputStream();
		out.write(("<!DOCTYPE html>\n" +
				"<html lang=\"zh\">\n" +
				"<head>\n" +
				"    <meta charset=\"UTF-8\">\n" +
				"    <title>Index</title>\n" +
				"</head>\n" +
				"<body>\n" +
				"   <a href='/TestServlet/'>示例Servlet</a><br/>\n" +
				"   <a href='/CMD/?cmd=pwd'>命令执行测试</a><br/>\n" +
				"   <a href='/info.php'>phpinfo()</a><br/>\n" +
				"</body>\n" +
				"").getBytes());

		out.flush();
		out.close();
	}

}
