package com.anbai.sec.rmi;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RMITestImpl extends UnicastRemoteObject implements RMITestInterface {

	private static final long serialVersionUID = 1L;

	protected RMITestImpl() throws RemoteException {
		super();
	}

	@Override
	public void test() throws RemoteException {
		System.out.println("Hello.RMI.");
	}

}