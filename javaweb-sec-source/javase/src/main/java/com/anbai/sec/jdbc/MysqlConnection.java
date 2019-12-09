package com.anbai.sec.jdbc;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Creator: yz
 * Date: 2019/12/9
 */
public class MysqlConnection {

	// 数据库驱动类名
	public static final String CLASS_NAME = "com.mysql.jdbc.Driver";

	// 数据库链接字符串
	public static final String URL = "jdbc:mysql://localhost:3306/mysql?autoReconnect=true&zeroDateTimeBehavior=round&useUnicode=true&characterEncoding=UTF-8&useOldAliasMetadataBehavior=true&useOldAliasMetadataBehavior=true&useSSL=false";

	// 数据库用户名
	public static final String USERNAME = "root";

	// 数据库密码
	public static final String PASSWORD = "root";

	/**
	 * 获取数据库链接对象
	 *
	 * @return JDBC Connection
	 * @throws ClassNotFoundException 驱动包未找到异常
	 * @throws SQLException           SQL异常
	 */
	public static Connection getConnection() throws ClassNotFoundException, SQLException {
		Class.forName(CLASS_NAME);// 注册JDBC驱动类
		return DriverManager.getConnection(URL, USERNAME, PASSWORD);
	}

}
