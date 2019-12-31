package com.anbai.sec.rmi;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServerTest {

	// RMI服务器IP地址
	public static final String RMI_HOST = "127.0.0.1";

	// RMI服务端口
	public static final int RMI_PORT = 9527;

	// RMI服务名称
	public static final String RMI_NAME = "rmi://" + RMI_HOST + ":" + RMI_PORT + "/test";

	public static void main(String[] args) {
		try {
			// 注册RMI端口
			LocateRegistry.createRegistry(RMI_PORT);

			// 绑定Remote对象
			Naming.bind(RMI_NAME, new RMITestImpl());

			System.out.println("RMI服务启动成功,服务地址:" + RMI_NAME);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}