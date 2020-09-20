package com.anbai.sec.vuls.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * SpringBoot SpEL表达式注入漏洞
 * Creator: yz
 * Date: 2020-04-29
 */
@Controller
public class SpELVulController {

	@RequestMapping("/SpELVulRCE.php")
	public String spELVulRCE(int id) {
		return "spel.jsp";
	}

}
