package com.anbai.sec.entity;

/**
 * Mysql User表实体类
 * Creator: yz
 * Date: 2020/1/7
 */
public class User {

	/**
	 * 主机名
	 */
	private String host;

	/**
	 * 用户名
	 */
	private String user;

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

}
