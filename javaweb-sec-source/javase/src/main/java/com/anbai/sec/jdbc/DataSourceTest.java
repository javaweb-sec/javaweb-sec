package com.anbai.sec.jdbc;

import com.alibaba.druid.pool.DruidDataSource;

import javax.sql.DataSource;

import static com.anbai.sec.jdbc.MysqlConnection.*;

/**
 * Creator: yz
 * Date: 2019/12/9
 */
public class DataSourceTest {

	/**
	 * 创建Druid数据源对象
	 *
	 * @return 返回数据源
	 */
	public static DataSource createDruidDataSource() {
		// 创建Druid数据源对象
		DruidDataSource dataSource = new DruidDataSource();

		dataSource.setUrl(URL);
		dataSource.setUsername(USERNAME);
		dataSource.setPassword(PASSWORD);
		dataSource.setDriverClassName(CLASS_NAME);

		return dataSource;
	}

	/**
	 * 获取数据源信息测试
	 */
	private static void getDataSourcePassword() {
		DataSource dataSource = createDruidDataSource();

		if (dataSource instanceof DruidDataSource) {
			DruidDataSource druidDataSource = (DruidDataSource) dataSource;

			System.out.println("URL:" + druidDataSource.getUrl());
			System.out.println("UserName:" + druidDataSource.getUsername());
			System.out.println("Password:" + druidDataSource.getPassword());
		}
	}

	public static void main(String[] args) {
		getDataSourcePassword();
	}

}
