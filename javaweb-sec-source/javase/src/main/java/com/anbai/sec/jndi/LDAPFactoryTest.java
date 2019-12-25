package com.anbai.sec.jndi;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

/**
 * Creator: yz
 * Date: 2019/12/24
 */
public class LDAPFactoryTest {

	public static void main(String[] args) {
		try {
			// 设置用户LDAP登陆用户DN
			String userDN = "cn=Manager,dc=javaweb,dc=org";

			// 设置登陆用户密码
			String password = "123456";

			// 创建环境变量对象
			Hashtable<String, Object> env = new Hashtable<String, Object>();

			// 设置JNDI初始化工厂类名
			env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

			// 设置JNDI提供服务的URL地址
			env.put(Context.PROVIDER_URL, "ldap://localhost:389");

			// 设置安全认证方式
			env.put(Context.SECURITY_AUTHENTICATION, "simple");

			// 设置用户信息
			env.put(Context.SECURITY_PRINCIPAL, userDN);

			// 设置用户密码
			env.put(Context.SECURITY_CREDENTIALS, password);

			// 创建LDAP连接
			DirContext ctx = new InitialDirContext(env);

			// 使用ctx可以查询或存储数据,此处省去业务代码

			ctx.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
