package com.anbai.sec.service;

import com.anbai.sec.dao.UserDAO;
import com.anbai.sec.entity.User;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

/**
 * Creator: yz
 * Date: 2020/1/7
 */
@Service
public class UserService {

	@Resource
	private UserDAO userDAO;

	public User findUserByUserAndHost(String user, String host) {
		return userDAO.findUserByUserAndHost(user, host);
	}

}
