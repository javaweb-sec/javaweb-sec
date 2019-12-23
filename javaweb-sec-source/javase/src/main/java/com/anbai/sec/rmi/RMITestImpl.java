package com.anbai.sec.rmi;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RMITestImpl extends UnicastRemoteObject implements RMITestInterface {

	private static final long serialVersionUID = 1L;

	protected RMITestImpl() throws RemoteException {
		super();
	}

	/**
	 * RMI测试方法
	 *
	 * @return 返回测试字符串
	 */
	@Override
	public String test() throws RemoteException {
		return "Hello RMI~";
	}

}