package com.anbai.shiro.spring.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author su18
 */
@Controller
@RequestMapping(value = "/index")
public class IndexController {


	@GetMapping(value = "/login")
	public void login(String username, String password, HttpServletResponse response) throws IOException {
		if ((username == null || username.equals("")) || (password == null || password.equals(""))) {
			response.getWriter().println("please login, params: username & password & rememberMe");
			return;
		}

		Subject               currentUser = SecurityUtils.getSubject();
		UsernamePasswordToken token       = new UsernamePasswordToken(username, password);

		try {
			currentUser.login(token);
			response.sendRedirect("/index/user");
		} catch (Exception e) {
			response.getWriter().println("username or password is incorrect!");
		}
	}

	@GetMapping(value = "/index")
	public void index(HttpServletResponse response) throws IOException {
		response.getWriter().println("this is index");
	}

	@GetMapping(value = "/unauth")
	public void unauth(HttpServletResponse response) throws IOException {
		response.getWriter().println("you are unauth,please login");
	}

	@GetMapping(value = "/user")
	public void user(HttpServletResponse response) throws IOException {
		response.getWriter().println("you have to login to view this page");
	}

}
