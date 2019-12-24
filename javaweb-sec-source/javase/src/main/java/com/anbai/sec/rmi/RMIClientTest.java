package com.anbai.sec.rmi;

import java.rmi.Naming;

import static com.anbai.sec.rmi.RMIServerTest.RMI_NAME;

public class RMIClientTest {

	public static void main(String[] args) {
		try {
			// 查找远程RMI服务
			RMITestInterface rt = (RMITestInterface) Naming.lookup(RMI_NAME);

			// 调用远程接口RMITestInterface类的test方法
			String result = rt.test();

			// 输出RMI方法调用结果
			System.out.println(result);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}