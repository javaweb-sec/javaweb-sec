package com.anbai.sec.jndi.injection;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import static com.anbai.sec.rmi.RMIServerTest.RMI_NAME;

/**
 * Creator: yz
 * Date: 2019/12/25
 */
public class RMIReferenceClientTest {

	public static void main(String[] args) {
		try {
//			// 测试时如果需要允许调用RMI远程引用对象加载请取消如下注释
//			System.setProperty("java.rmi.server.useCodebaseOnly", "false");
//			System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");

			InitialContext context = new InitialContext();

			// 获取RMI绑定的恶意ReferenceWrapper对象
			Object obj = context.lookup(RMI_NAME);

			System.out.println(obj);
		} catch (NamingException e) {
			e.printStackTrace();
		}
	}

}
