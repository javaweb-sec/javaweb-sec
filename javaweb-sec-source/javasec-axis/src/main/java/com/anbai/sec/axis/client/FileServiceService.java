/**
 * FileServiceService.java
 * <p>
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.4 Apr 22, 2006 (06:55:48 PDT) WSDL2Java emitter.
 */

package com.anbai.sec.axis.client;

public interface FileServiceService extends javax.xml.rpc.Service {

	java.lang.String getFileServiceAddress();

	FileService_PortType getFileService() throws javax.xml.rpc.ServiceException;

	FileService_PortType getFileService(java.net.URL portAddress) throws javax.xml.rpc.ServiceException;

}
