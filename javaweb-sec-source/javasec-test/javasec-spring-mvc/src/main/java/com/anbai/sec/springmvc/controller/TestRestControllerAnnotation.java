package com.anbai.sec.springmvc.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class TestRestControllerAnnotation {

	@RequestMapping("/testRestControllerAnnotation.do")
	public String handleRequest(HttpServletRequest request, HttpServletResponse response) {
		return "controller/test_rest_controller_annotation";
	}

}