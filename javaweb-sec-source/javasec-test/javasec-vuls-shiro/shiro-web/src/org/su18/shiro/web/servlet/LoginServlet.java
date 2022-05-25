package org.su18.shiro.web.servlet;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

/**
 * 登陆 Servlet
 *
 * @author su18
 */
public class LoginServlet extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {


//		if ((username == null || username.equals("")) || (password == null || password.equals(""))) {
//			resp.getWriter().println("please login, params: username & password & rememberMe");
//			return;
//		}
		Subject currentUser = SecurityUtils.getSubject();
		String  password    = req.getParameter("password");

		if (!currentUser.isAuthenticated()) {

			if (password == null) {
				resp.getWriter().println("please login");
				return;
			}

			String username = req.getParameter("username");

			UsernamePasswordToken token = new UsernamePasswordToken(username, password, true);

			try {
				currentUser.login(token);
				resp.sendRedirect("user");
			} catch (UnknownAccountException e) {
				resp.getWriter().println("Unknown user account...");
			} catch (IncorrectCredentialsException e) {
				resp.getWriter().println("Incorrect credentials...");
			} catch (DisabledAccountException e) {
				resp.getWriter().println("User account disabled...");
			} catch (AuthenticationException e) {
				resp.getWriter().println("Authentication Exception...");
				resp.getWriter().println(e);
				resp.getWriter().println(Arrays.toString(e.getStackTrace()));
			}
		} else {
			resp.getWriter().println("Hello:" + currentUser.getPrincipal());
		}


	}
}
