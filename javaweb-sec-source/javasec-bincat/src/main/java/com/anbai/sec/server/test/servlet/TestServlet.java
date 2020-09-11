package com.anbai.sec.server.test.servlet;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

@WebServlet(name = "TestServlet", urlPatterns = "/TestServlet/")
public class TestServlet extends HttpServlet {

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		doPost(request, response);
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
		OutputStream out = response.getOutputStream();
		out.write(("Hello....<br/>Request Method:" + request.getMethod() + "<br/>Class:" + this.getClass()).getBytes());
	}

}
