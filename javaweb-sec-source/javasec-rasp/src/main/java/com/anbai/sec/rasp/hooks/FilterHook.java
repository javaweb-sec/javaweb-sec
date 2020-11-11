/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.hooks;

import com.anbai.sec.rasp.annotation.RASPClassHook;
import com.anbai.sec.rasp.annotation.RASPMethodHook;
import com.anbai.sec.rasp.commons.RASPHookResult;
import com.anbai.sec.rasp.commons.RASPMethodAdvice;
import com.anbai.sec.rasp.hooks.handler.FilterAndServletHookHandler;

import static com.anbai.sec.rasp.hooks.handler.FilterAndServletHookHandler.onRequestExit;

/**
 * Filter Hook类,Hook 所有Filter实现类的doFilter方法
 * Creator: yz
 * Date: 2019-07-23
 */
@RASPClassHook
public class FilterHook {

	@RASPMethodHook(
			superClass = "javax.servlet.Filter", methodName = "doFilter",
			methodArgs = {"javax.servlet.ServletRequest", "javax.servlet.ServletResponse", "javax.servlet.FilterChain"}
	)
	public static class FilterDoFilterHook extends RASPMethodAdvice {

		public RASPHookResult<?> onMethodEnter() {
			return FilterAndServletHookHandler.onRequestEnter(this);
		}

		public RASPHookResult<?> onMethodExit() {
			return onRequestExit(this);
		}

	}

}