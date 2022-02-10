package org.su18.shiro.web.servlet;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author su18
 */
public class AdminServlet extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.getWriter().println("Hi, this is AdminServlet, you must login and be an administrator to view this page.");
		resp.getWriter().println(SecurityUtils.getSubject().getPrincipal());
	}
}
