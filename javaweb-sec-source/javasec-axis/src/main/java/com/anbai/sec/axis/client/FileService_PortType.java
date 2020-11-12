/**
 * FileService_PortType.java
 * <p>
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.4 Apr 22, 2006 (06:55:48 PDT) WSDL2Java emitter.
 */

package com.anbai.sec.axis.client;

public interface FileService_PortType extends java.rmi.Remote {

	java.lang.String readFile(java.lang.String path) throws java.rmi.RemoteException;

	java.lang.String writeFile(java.lang.String path, java.lang.String content) throws java.rmi.RemoteException;

}
