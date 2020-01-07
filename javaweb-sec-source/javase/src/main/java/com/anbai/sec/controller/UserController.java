package com.anbai.sec.controller;

import com.anbai.sec.entity.User;
import com.anbai.sec.service.UserService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

/**
 * Creator: yz
 * Date: 2020/1/7
 */
@RestController
@RequestMapping("/user/")
public class UserController {

	@Resource
	private UserService userService;

	@RequestMapping("/findUser.php")
	public User index(User user) {
		return userService.findUserByUserAndHost(user.getUser(), user.getHost());
	}

}
