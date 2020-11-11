/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import static com.anbai.sec.rasp.commons.RASPConstants.AGENT_NAME;
import static com.anbai.sec.rasp.commons.RASPHookHandlerType.RETURN;
import static com.anbai.sec.rasp.commons.RASPMethodAdviceEvent.*;
import static com.anbai.sec.rasp.context.RASPRequestContextManager.hasRequest;

/**
 * Creator: yz
 * Date: 2019-07-09
 */
public class RASPHookProxy {

	private static final ClassLoader SYSTEM_CLASSLOADER = ClassLoader.getSystemClassLoader();

	private static final SelfCallBarrier SELF_CALL_BARRIER = new SelfCallBarrier();

	/**
	 * Hook方法进入调用此方法
	 *
	 * @param args           方法参数值数组
	 * @param callbackClass  目标类
	 * @param thisClassName  调用类名
	 * @param methodName     方法名
	 * @param methodArgsDesc 方法参数描述符
	 * @param thisObject     调用类实例this对象(static方法默认为null)
	 * @return Hook方法处理结果
	 */
	public static RASPHookResult<?> onMethodEnter(Object[] args, String callbackClass, String thisClassName,
	                                              String methodName, String methodArgsDesc, Object thisObject) {

		return invokeAdvice(
				callbackClass, null, args, methodName, methodArgsDesc,
				thisObject, thisClassName, ON_METHOD_ENTER
		);
	}

	/**
	 * Hook方法退出后回调此方法
	 *
	 * @param returnValue    返回值(没有返回值传入null)
	 * @param args           方法参数值数组
	 * @param callbackClass  目标类
	 * @param thisClassName  调用类名
	 * @param methodName     方法名
	 * @param methodArgsDesc 方法参数描述符
	 * @param thisObject     调用类实例this对象(static方法默认为null)
	 * @return Hook方法处理结果
	 */
	public static RASPHookResult<?> onMethodExit(
			Object returnValue, Object[] args, String callbackClass, String thisClassName,
			String methodName, String methodArgsDesc, Object thisObject) {

		return invokeAdvice(
				callbackClass, returnValue, args, methodName, methodArgsDesc,
				thisObject, thisClassName, ON_METHOD_EXIT
		);
	}

	private static RASPHookResult<?> invokeAdvice(
			String callbackClass, Object returnValue, Object[] args,
			String methodName, String methodArgsDesc, Object thisObject,
			String thisClassName, RASPMethodAdviceEvent event) {

		RASPHookResult<?> result = new RASPHookResult(RETURN);
		Thread            thread = Thread.currentThread();

		if (SELF_CALL_BARRIER.isEnter(thread)) {
			return result;
		}

		final SelfCallBarrier.Node node = SELF_CALL_BARRIER.enter(thread);

		try {
			Class<?> clazz = SYSTEM_CLASSLOADER.loadClass(callbackClass);

			if (RASPMethodAdvice.class.isAssignableFrom(clazz)) {
				// 创建调用类实例
				RASPMethodAdvice advice = (RASPMethodAdvice) clazz.newInstance();

				advice.setArgs(args);
				advice.setReturnValue(returnValue);
				advice.setMethodName(methodName);
				advice.setMethodArgsDesc(methodArgsDesc);
				advice.setThisObject(thisObject);
				advice.setThisClassName(thisClassName);

				// 调用Hook点注册的Advice方法
				if (ON_METHOD_ENTER.equals(event)) {
					result = advice.onMethodEnter();
				} else if (ON_METHOD_EXIT.equals(event)) {
					result = advice.onMethodExit();
				} else if (ON_METHOD_THROW.equals(event)) {
					result = advice.onMethodThrow();
				}

				// 获取Hook返回结果处理类型
				RASPHookHandlerType type = result.getRaspHookHandlerType();

				// 如果是静默模式因为只需要记录不用拦截,所以需要强制修改Hook处理结果类型为RETURN,但是需要排除Hook点强制替换的结果
				if (hasRequest() && type != RETURN && !result.isForceReplace()) {
					result.setRaspHookHandlerType(RETURN);
				}

//				// 结束Hook处理逻辑,清理context、记录日志，如果Hook处理结果是REPLACE_OR_BLOCK或者THROW也
//				// 必须清除context，因为Filter和Servlet的iswaf.api的请求会返回一个REPLACE_OR_BLOCK
//				if (event == ON_METHOD_EXIT || event == ON_METHOD_THROW || type == REPLACE_OR_BLOCK || type == THROW) {
//					finishHook(advice.getThisObject(), type);
//				}
			}
		} catch (Throwable t) {
			new RuntimeException(AGENT_NAME + "处理调用Hook点异常:" + t, t).printStackTrace();
		} finally {
			SELF_CALL_BARRIER.exit(thread, node);
		}

		return result;
	}

}
