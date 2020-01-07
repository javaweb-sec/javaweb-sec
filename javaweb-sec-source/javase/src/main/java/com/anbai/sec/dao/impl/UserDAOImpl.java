package com.anbai.sec.dao.impl;

import com.anbai.sec.dao.UserDAO;
import com.anbai.sec.entity.User;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

/**
 * Creator: yz
 * Date: 2020/1/7
 */
@Component
public class UserDAOImpl implements UserDAO {

	@Resource
	private JdbcTemplate jdbcTemplate;

	@Override
	public User findUserByUserAndHost(String user, String host) {
		// SQL注入示例
		String sql = "select host,user from mysql.user where user = ? and host = '" + host + "'";

		return jdbcTemplate.queryForObject(
				sql, new Object[]{user},
				BeanPropertyRowMapper.newInstance(User.class)
		);
	}

}
