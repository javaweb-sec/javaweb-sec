package com.anbai.sec.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Creator: yz
 * Date: 2019/12/9
 */
@Controller
public class IndexController {

	@RequestMapping("/index.php")
	public String index(String username, HttpServletRequest request, HttpServletResponse response) {
		request.setAttribute("username", username);
		return "/index.jsp";
	}

}
