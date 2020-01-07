package com.anbai.sec.dao;

import com.anbai.sec.entity.User;

/**
 * Creator: yz
 * Date: 2020/1/7
 */
public interface UserDAO {

	User findUserByUserAndHost(String user, String host);

}
