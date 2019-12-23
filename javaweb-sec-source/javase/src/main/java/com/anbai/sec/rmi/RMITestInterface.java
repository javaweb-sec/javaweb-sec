package com.anbai.sec.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * RMI测试接口
 */
public interface RMITestInterface extends Remote {

	/**
	 * RMI测试方法
	 *
	 * @return 返回测试字符串
	 */
	String test() throws RemoteException;

}