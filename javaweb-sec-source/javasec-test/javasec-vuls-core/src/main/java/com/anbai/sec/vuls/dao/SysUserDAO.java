package com.anbai.sec.vuls.dao;

import com.anbai.sec.vuls.entity.SysUser;
import org.javaweb.utils.StringUtils;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

/**
 * Creator: yz
 * Date: 2020-05-05
 */
@Component
public class SysUserDAO {

	@Resource
	private JdbcTemplate jdbcTemplate;

	public SysUser getSysUserByUsername(String username) {
		try {
			String sql = "select * from sys_user where username = '" + username + "'";

			return jdbcTemplate.queryForObject(
					sql, BeanPropertyRowMapper.newInstance(SysUser.class)
			);
		} catch (DataAccessException e) {
			return null;
		}
	}

	public SysUser getSysUserByID(String id) {
		try {
			String sql = "select * from sys_user where id = '" + id + "'";

			return jdbcTemplate.queryForObject(
					sql, BeanPropertyRowMapper.newInstance(SysUser.class)
			);
		} catch (DataAccessException e) {
			return null;
		}
	}

	public SysUser login(String username, String password) {
		try {
			String sql = "select * from sys_user where username = '" +
					username + "' and password = '" + password + "'";

			return jdbcTemplate.queryForObject(
					sql, BeanPropertyRowMapper.newInstance(SysUser.class)
			);
		} catch (DataAccessException e) {
			return null;
		}
	}

	public int register(SysUser u) {
		String defaultAvatar = "/res/images/avatar/default.png";
		String registerTime  = StringUtils.getCurrentTime();

		String sql = "insert into sys_user (username, password, user_avatar, register_time) values" +
				" ('" + u.getUsername() + "', '" + u.getPassword() + "', '" +
				defaultAvatar + "', '" + registerTime + "')";

		return jdbcTemplate.update(sql);
	}

}
