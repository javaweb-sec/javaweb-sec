package com.anbai.sec.jndi;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

import static com.anbai.sec.rmi.RMIServerTest.RMI_HOST;
import static com.anbai.sec.rmi.RMIServerTest.RMI_PORT;

/**
 * Creator: yz
 * Date: 2019/12/24
 */
public class RMIRegistryContextFactoryTest {

	public static void main(String[] args) {
		String providerURL = "rmi://" + RMI_HOST + ":" + RMI_PORT;

		// 创建环境变量对象
		Hashtable env = new Hashtable();

		// 设置JNDI初始化工程类名
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");

		// 设置JNDI提供服务的URL地址
		env.put(Context.PROVIDER_URL, providerURL);

		try {
			// 注册JNDI目录服务
			DirContext context = new InitialDirContext(env);

			// 获取所有RMI服务名
			NamingEnumeration enumeration = context.list("");

			// 遍历并输出RMI服务名称
			while (enumeration.hasMore()) {
				System.out.println(enumeration.next());
			}
		} catch (NamingException e) {
			e.printStackTrace();
		}
	}

}
