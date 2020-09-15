package com.anbai.sec.test.springboot.controller;

import org.javaweb.utils.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Controller
public class SysUserController {

	@ResponseBody
	@RequestMapping("/login.do")
	public Map<String, String> login(String username, String password) {
		Map<String, String> map = new HashMap<String, String>();

		map.put("token", StringUtils.getUUID());
		map.put("username", username);
		map.put("password", password);

		return map;
	}

}
