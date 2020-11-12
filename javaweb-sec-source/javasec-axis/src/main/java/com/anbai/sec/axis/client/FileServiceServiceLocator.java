/**
 * FileServiceServiceLocator.java
 * <p>
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.4 Apr 22, 2006 (06:55:48 PDT) WSDL2Java emitter.
 */

package com.anbai.sec.axis.client;

public class FileServiceServiceLocator extends org.apache.axis.client.Service implements FileServiceService {

	public FileServiceServiceLocator() {
	}


	public FileServiceServiceLocator(org.apache.axis.EngineConfiguration config) {
		super(config);
	}

	public FileServiceServiceLocator(java.lang.String wsdlLoc, javax.xml.namespace.QName sName) throws javax.xml.rpc.ServiceException {
		super(wsdlLoc, sName);
	}

	// Use to get a proxy class for FileService
	private java.lang.String FileService_address = "http://localhost:8080/services/FileService";

	public java.lang.String getFileServiceAddress() {
		return FileService_address;
	}

	// The WSDD service name defaults to the port name.
	private java.lang.String FileServiceWSDDServiceName = "FileService";

	public java.lang.String getFileServiceWSDDServiceName() {
		return FileServiceWSDDServiceName;
	}

	public void setFileServiceWSDDServiceName(java.lang.String name) {
		FileServiceWSDDServiceName = name;
	}

	public FileService_PortType getFileService() throws javax.xml.rpc.ServiceException {
		java.net.URL endpoint;
		try {
			endpoint = new java.net.URL(FileService_address);
		} catch (java.net.MalformedURLException e) {
			throw new javax.xml.rpc.ServiceException(e);
		}
		return getFileService(endpoint);
	}

	public FileService_PortType getFileService(java.net.URL portAddress) throws javax.xml.rpc.ServiceException {
		try {
			FileServiceSoapBindingStub _stub = new FileServiceSoapBindingStub(portAddress, this);
			_stub.setPortName(getFileServiceWSDDServiceName());
			return _stub;
		} catch (org.apache.axis.AxisFault e) {
			return null;
		}
	}

	public void setFileServiceEndpointAddress(java.lang.String address) {
		FileService_address = address;
	}

	/**
	 * For the given interface, get the stub implementation.
	 * If this service has no port for the given interface,
	 * then ServiceException is thrown.
	 */
	public java.rmi.Remote getPort(Class serviceEndpointInterface) throws javax.xml.rpc.ServiceException {
		try {
			if (FileService_PortType.class.isAssignableFrom(serviceEndpointInterface)) {
				FileServiceSoapBindingStub _stub = new FileServiceSoapBindingStub(new java.net.URL(FileService_address), this);
				_stub.setPortName(getFileServiceWSDDServiceName());
				return _stub;
			}
		} catch (java.lang.Throwable t) {
			throw new javax.xml.rpc.ServiceException(t);
		}
		throw new javax.xml.rpc.ServiceException("There is no stub implementation for the interface:  " + (serviceEndpointInterface == null ? "null" : serviceEndpointInterface.getName()));
	}

	/**
	 * For the given interface, get the stub implementation.
	 * If this service has no port for the given interface,
	 * then ServiceException is thrown.
	 */
	public java.rmi.Remote getPort(javax.xml.namespace.QName portName, Class serviceEndpointInterface) throws javax.xml.rpc.ServiceException {
		if (portName == null) {
			return getPort(serviceEndpointInterface);
		}
		java.lang.String inputPortName = portName.getLocalPart();
		if ("FileService".equals(inputPortName)) {
			return getFileService();
		} else {
			java.rmi.Remote _stub = getPort(serviceEndpointInterface);
			((org.apache.axis.client.Stub) _stub).setPortName(portName);
			return _stub;
		}
	}

	public javax.xml.namespace.QName getServiceName() {
		return new javax.xml.namespace.QName("http://localhost:8080/services/FileService", "FileServiceService");
	}

	private java.util.HashSet ports = null;

	public java.util.Iterator getPorts() {
		if (ports == null) {
			ports = new java.util.HashSet();
			ports.add(new javax.xml.namespace.QName("http://localhost:8080/services/FileService", "FileService"));
		}
		return ports.iterator();
	}

	/**
	 * Set the endpoint address for the specified port name.
	 */
	public void setEndpointAddress(java.lang.String portName, java.lang.String address) throws javax.xml.rpc.ServiceException {

		if ("FileService".equals(portName)) {
			setFileServiceEndpointAddress(address);
		} else { // Unknown Port Name
			throw new javax.xml.rpc.ServiceException(" Cannot set Endpoint Address for Unknown Port" + portName);
		}
	}

	/**
	 * Set the endpoint address for the specified port name.
	 */
	public void setEndpointAddress(javax.xml.namespace.QName portName, java.lang.String address) throws javax.xml.rpc.ServiceException {
		setEndpointAddress(portName.getLocalPart(), address);
	}

}
