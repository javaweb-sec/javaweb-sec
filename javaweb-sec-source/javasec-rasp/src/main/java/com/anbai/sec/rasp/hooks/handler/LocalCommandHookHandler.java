/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.hooks.handler;

import com.anbai.sec.rasp.commons.RASPHookResult;
import com.anbai.sec.rasp.commons.RASPMethodAdvice;
import com.anbai.sec.rasp.exception.RASPHookException;

import static com.anbai.sec.rasp.commons.RASPHookHandlerType.THROW;
import static com.anbai.sec.rasp.context.RASPRequestContextManager.hasRequest;

/**
 * Creator: yz
 * Date: 2019-07-23
 */
public class LocalCommandHookHandler {

	/**
	 * 本地命令执行拦截模块,如果当前URL是白名单或命令执行拦截模块未开启则不拦截,否则一律拦截
	 *
	 * @param commands   命令参数数组
	 * @param thisObject this
	 * @param advice     RASPMethodAdvice
	 * @return 检测结果
	 */
	public static RASPHookResult<?> processCommand(String[] commands, Object thisObject, RASPMethodAdvice advice) {
		if (hasRequest()) {
			// 检测当前请求是否需要经过安全模块检测和过滤且该模块是否是开启状态
			return new RASPHookResult(THROW, new RASPHookException("CMD"));
		}

//		return new RASPHookResult(RETURN);
		return new RASPHookResult(THROW, new RASPHookException("CMD"));
	}

}
