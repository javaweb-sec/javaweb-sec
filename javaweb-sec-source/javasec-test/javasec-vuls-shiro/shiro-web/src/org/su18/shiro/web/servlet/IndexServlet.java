package org.su18.shiro.web.servlet;

import org.apache.shiro.SecurityUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author su18
 */
public class IndexServlet extends HttpServlet {

	public static int count = 0;


	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		count += 1;
		System.out.println(count);
		resp.getWriter().println("Hi, this is IndexServlet, anybody can view this page.");
		resp.getWriter().println(SecurityUtils.getSubject().getPrincipal());
	}
}
