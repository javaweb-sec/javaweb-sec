package com.anbai.sec.rmi;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServerTest {

	public static void main(String[] args) {
		try {
			int    port    = 9527;
			String rmiName = "rmi://127.0.0.1:" + port + "/test";

			// 注册RMI端口
			LocateRegistry.createRegistry(port);

			// 绑定Remote对象
			Naming.bind(rmiName, new RMITestImpl());

			System.out.println("RMI服务启动成功,服务地址:" + rmiName);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}