package com.anbai.sec.jndi;

import com.anbai.sec.rmi.RMITestInterface;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.rmi.RemoteException;
import java.util.Hashtable;

import static com.anbai.sec.rmi.RMIServerTest.*;

/**
 * Creator: yz
 * Date: 2019/12/24
 */
public class RMIRegistryContextFactoryTest {

	public static void main(String[] args) {
		String providerURL = "rmi://" + RMI_HOST + ":" + RMI_PORT;

		// 创建环境变量对象
		Hashtable env = new Hashtable();

		// 设置JNDI初始化工厂类名
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");

		// 设置JNDI提供服务的URL地址
		env.put(Context.PROVIDER_URL, providerURL);

		// 通过JNDI调用远程RMI方法测试，等同于com.anbai.sec.rmi.RMIClientTest类的Demo
		try {
			// 创建JNDI目录服务对象
			DirContext context = new InitialDirContext(env);

			// 通过命名服务查找远程RMI绑定的RMITestInterface对象
			RMITestInterface testInterface = (RMITestInterface) context.lookup(RMI_NAME);

			// 调用远程的RMITestInterface接口的test方法
			String result = testInterface.test();

			System.out.println(result);
		} catch (NamingException e) {
			e.printStackTrace();
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

}
