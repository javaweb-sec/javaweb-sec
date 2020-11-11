/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.hooks.handler;

import com.anbai.sec.rasp.commons.RASPHookResult;
import com.anbai.sec.rasp.commons.RASPMethodAdvice;

import static com.anbai.sec.rasp.commons.RASPHookHandlerType.RETURN;

/**
 * 灵蜥Filter和Servlet入口Hook处理类
 */
public class FilterAndServletHookHandler {

	/**
	 * Filter和Servlet请求进入事件
	 *
	 * @param advice RASPMethodAdvice
	 * @return Hook处理结果
	 */
	public static RASPHookResult<?> onRequestEnter(RASPMethodAdvice advice) {
		return new RASPHookResult(RETURN);
	}

	/**
	 * 处理Filter和Servlet请求结束事件
	 *
	 * @param advice RASPMethodAdvice
	 * @return Hook处理结果
	 */
	public static RASPHookResult<?> onRequestExit(RASPMethodAdvice advice) {
		// 暂不需要处理Servlet/Filter类的退出事件
		return new RASPHookResult(RETURN);
	}

}