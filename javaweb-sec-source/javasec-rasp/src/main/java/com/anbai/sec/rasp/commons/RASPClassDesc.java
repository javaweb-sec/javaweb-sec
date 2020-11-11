/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import javassist.CtClass;

public class RASPClassDesc {

	/**
	 * 类访问级别
	 */
	private final int access;

	/**
	 * 类名
	 */
	private final String className;

	/**
	 * 签名
	 */
	private final String signature;

	/**
	 * 父类名
	 */
	private final CtClass superClassName;

	/**
	 * 实现的所有的接口名
	 */
	private final CtClass[] interfacesClass;

	/**
	 * 类加载器
	 */
	private final ClassLoader classLoader;

	/**
	 * 类字节码
	 */
	private final byte[] classfileBuffer;

	public RASPClassDesc(final int access, final String className,
						 final String signature, final CtClass superClassName,
						 final CtClass[] interfacesClass, final ClassLoader classLoader,
						 final byte[] classfileBuffer) {

		this.access = access;
		this.className = className;
		this.signature = signature;
		this.superClassName = superClassName;
		this.interfacesClass = interfacesClass;
		this.classLoader = classLoader;
		this.classfileBuffer = classfileBuffer;
	}

	public int getAccess() {
		return access;
	}

	public String getClassName() {
		return className;
	}

	public String getSignature() {
		return signature;
	}

	public CtClass getSuperClassName() {
		return superClassName;
	}

	public CtClass[] getInterfacesClass() {
		return interfacesClass;
	}

	public ClassLoader getClassLoader() {
		return classLoader;
	}

	public byte[] getClassfileBuffer() {
		return classfileBuffer;
	}

}