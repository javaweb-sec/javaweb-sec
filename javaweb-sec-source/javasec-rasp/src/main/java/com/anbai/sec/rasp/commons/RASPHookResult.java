/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import com.anbai.sec.rasp.exception.RASPHookException;

/**
 * Creator: yz
 * Date: 2019-06-20
 */
public class RASPHookResult<T> {

	/**
	 * Hook结果处理方式
	 */
	private RASPHookHandlerType raspHookHandlerType;

	/**
	 * Hook抛出的异常,如果HookMethodType的值为THROW那么exception的值必须设置
	 */
	private RASPHookException exception;

	/**
	 * Hook返回值,如果Hook的方法有返回值且HookMethodType的值为REPLACE,那么returnValue值必须被修改
	 */
	private T returnValue;

	/**
	 * 是否强制阻断
	 */
	private boolean forceReplace = false;

	public RASPHookResult(RASPHookHandlerType handlerType) {
		this.raspHookHandlerType = handlerType;
	}

	public RASPHookResult(RASPHookHandlerType handlerType, T returnValue) {
		this.raspHookHandlerType = handlerType;
		this.returnValue = returnValue;
	}

	public RASPHookResult(RASPHookHandlerType handlerType, T returnValue, boolean forceReplace) {
		this.raspHookHandlerType = handlerType;
		this.returnValue = returnValue;
		this.forceReplace = forceReplace;
	}

	public RASPHookResult(RASPHookHandlerType handlerType, RASPHookException exception) {
		this.raspHookHandlerType = handlerType;
		this.exception = exception;
	}

	/**
	 * 创建Hook处理结果对象
	 *
	 * @param handlerType Hook处理类型
	 * @param exception   异常
	 * @param returnValue 返回值
	 */
	public RASPHookResult(RASPHookHandlerType handlerType, RASPHookException exception, T returnValue) {
		this.raspHookHandlerType = handlerType;
		this.exception = exception;
		this.returnValue = returnValue;
	}

	public RASPHookHandlerType getRaspHookHandlerType() {
		return raspHookHandlerType;
	}

	public void setRaspHookHandlerType(RASPHookHandlerType raspHookHandlerType) {
		this.raspHookHandlerType = raspHookHandlerType;
	}

	public RASPHookException getException() {
		return exception;
	}

	public void setException(RASPHookException exception) {
		this.exception = exception;
	}

	public T getReturnValue() {
		return returnValue;
	}

	public void setReturnValue(T returnValue) {
		this.returnValue = returnValue;
	}

	public boolean isForceReplace() {
		return forceReplace;
	}

	public void setForceReplace(boolean forceReplace) {
		this.forceReplace = forceReplace;
	}

}
