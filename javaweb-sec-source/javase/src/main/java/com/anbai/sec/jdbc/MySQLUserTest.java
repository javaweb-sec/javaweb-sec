package com.anbai.sec.jdbc;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Creator: yz
 * Date: 2019/12/8
 */
public class MySQLUserTest {

	public static void main(String[] args) {
		try {
			Connection connection = MysqlConnection.getConnection();

			System.out.println(connection);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (SQLException e) {
			e.printStackTrace();
		}

	}

}
