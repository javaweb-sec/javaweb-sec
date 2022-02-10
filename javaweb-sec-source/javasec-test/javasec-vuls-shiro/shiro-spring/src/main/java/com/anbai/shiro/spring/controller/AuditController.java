package com.anbai.shiro.spring.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author su18
 */

@Controller
@RequestMapping(value = "/audit")
public class AuditController {


	@GetMapping(value = "/list")
	public void list(HttpServletResponse response) throws IOException {
		response.getWriter().println("you have to be auditor to view this page");
	}


	@GetMapping(value = "/{name}")
	public void list(@PathVariable String name, HttpServletResponse response) throws IOException {
		response.getWriter().println("no need auth to see this page:" + name);
	}
}
