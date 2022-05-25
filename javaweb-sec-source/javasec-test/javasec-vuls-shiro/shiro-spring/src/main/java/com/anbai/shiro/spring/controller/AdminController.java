package com.anbai.shiro.spring.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author su18
 */
@Controller
@RequestMapping(value = " ")
public class AdminController {


	@GetMapping(value = "/list")
	public void list(HttpServletResponse response) throws IOException {
		response.getWriter().println("you have to be admin to view this page");
	}

	@GetMapping(value = " ")
	public void list2(HttpServletResponse response) throws IOException {
		response.getWriter().println("null nan nil");
	}
}
