package com.anbai.sec.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface RMITestInterface extends Remote {

	void test() throws RemoteException;

}