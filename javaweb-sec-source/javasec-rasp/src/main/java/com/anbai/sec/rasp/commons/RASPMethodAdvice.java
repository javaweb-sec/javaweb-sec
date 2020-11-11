/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import static com.anbai.sec.rasp.commons.RASPHookHandlerType.RETURN;

/**
 * 灵蜥Hook方法增强
 * Creator: yz
 * Date: 2019-07-08
 */
public class RASPMethodAdvice {

	/**
	 * Hook方法返回值
	 */
	private Object returnValue;

	/**
	 * Hook方法参数
	 */
	private Object[] args;

	/**
	 * Hook方法名
	 */
	private String methodName;

	/**
	 * Hook方法参数描述符
	 */
	private String methodArgsDesc;

	/**
	 * Hook类实例对象，如果是static方法这个值为null
	 */
	private Object thisObject;

	/**
	 * Hook类名称
	 */
	private String thisClassName;

	/**
	 * 发起API调用的类对象
	 */
	private String invokeClassName;

	/**
	 * Hook调用链
	 */
	private StackTraceElement[] traceElements;

	/**
	 * 获取返回值,如果方法无返回值return null
	 *
	 * @return 返回值对象
	 */
	public <T> T getReturnValue() {
		return (T) returnValue;
	}

	/**
	 * 设置返回值
	 *
	 * @param returnValue 返回值
	 */
	public void setReturnValue(Object returnValue) {
		this.returnValue = returnValue;
	}

	/**
	 * 获取Hook方法的所有的参数
	 *
	 * @return 参数数组
	 */
	public Object[] getArgs() {
		return args;
	}

	/**
	 * 设置Hook参数值数组
	 *
	 * @param args 参数数组
	 */
	public void setArgs(Object[] args) {
		this.args = args;
	}

	/**
	 * 通过传入参数数组下标获取Hook方法的单个参数值
	 *
	 * @param index 索引
	 * @param <T>
	 * @return 索引对应的类型
	 */
	public <T> T getArg(int index) {
		if (args.length > index) {
			return (T) args[index];
		}

		return null;
	}

	/**
	 * 获取Hook方法名
	 *
	 * @return 方法名
	 */
	public String getMethodName() {
		return methodName;
	}

	/**
	 * 设置Hook方法名
	 *
	 * @param methodName 方法名
	 */
	public void setMethodName(String methodName) {
		this.methodName = methodName;
	}

	/**
	 * 获取Hook方法参数描述符
	 *
	 * @return 方法描述符
	 */
	public String getMethodArgsDesc() {
		return methodArgsDesc;
	}

	/**
	 * 设置Hook方法参数描述符
	 *
	 * @param methodArgsDesc 方法描述符
	 */
	public void setMethodArgsDesc(String methodArgsDesc) {
		this.methodArgsDesc = methodArgsDesc;
	}

	/**
	 * 获取Hook类实例对象，如果是static方法这个值为null
	 *
	 * @return 类实例
	 */
	public Object getThisObject() {
		return thisObject;
	}

	/**
	 * 设置Hook类实例对象
	 *
	 * @param thisObject 类实例
	 */
	public void setThisObject(Object thisObject) {
		this.thisObject = thisObject;
	}

	/**
	 * 获取Hook调用类类名
	 *
	 * @return 类名
	 */
	public String getThisClassName() {
		return thisClassName;
	}

	/**
	 * 设置Hook调用类类名
	 *
	 * @param thisClassName 类名
	 */
	public void setThisClassName(String thisClassName) {
		this.thisClassName = thisClassName;
	}

	/**
	 * 获取发起API调用的类
	 *
	 * @return
	 */
	public String getInvokeClassName() {
		return invokeClassName;
	}

	/**
	 * 设置发起API调用的类
	 *
	 * @param invokeClassName
	 */
	public void setInvokeClassName(String invokeClassName) {
		this.invokeClassName = invokeClassName;
	}

	/**
	 * 获取Hook调用链
	 *
	 * @return 堆栈信息
	 */
	public StackTraceElement[] getTraceElements() {
		return traceElements;
	}

	/**
	 * 设置Hook调用链
	 *
	 * @param traceElements 堆栈信息
	 */
	public void setTraceElements(StackTraceElement[] traceElements) {
		this.traceElements = traceElements;
	}

	/**
	 * Hook方法进入调用此方法
	 *
	 * @return 灵蜥Hook处理结果
	 */
	public RASPHookResult onMethodEnter() {
		return new RASPHookResult(RETURN);
	}

	/**
	 * Hook方法退出后回调此方法
	 *
	 * @return 灵蜥Hook处理结果
	 */
	public RASPHookResult onMethodExit() {
		return new RASPHookResult(RETURN);
	}

	/**
	 * Hook方法抛出异常退出后回调此方法
	 *
	 * @return 灵蜥Hook处理结果
	 */
	public RASPHookResult onMethodThrow() {
		return new RASPHookResult(RETURN);
	}

}
