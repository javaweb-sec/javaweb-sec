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

import static com.anbai.sec.rasp.hooks.handler.FilterAndServletHookHandler.onRequestEnter;
import static com.anbai.sec.rasp.hooks.handler.FilterAndServletHookHandler.onRequestExit;

/**
 * Servlet Hook类,Hook 所有Servlet子类的service方法
 * Creator: yz
 * Date: 2019-06-21
 */
@RASPClassHook
public class ServletHook {

	@RASPMethodHook(
			superClass = "javax.servlet.Servlet", methodName = "service",
			methodArgs = {"javax.servlet.http.HttpServletRequest", "javax.servlet.http.HttpServletResponse"}
	)
	public static class ServletServiceHook extends RASPMethodAdvice {

		public RASPHookResult<?> onMethodEnter() {
			return onRequestEnter(this);
		}

		public RASPHookResult<?> onMethodExit() {
			return onRequestExit(this);
		}

	}

	@RASPMethodHook(
			superClass = "javax.servlet.jsp.HttpJspPage", methodName = "_jspService",
			methodArgs = {"javax.servlet.http.HttpServletRequest", "javax.servlet.http.HttpServletResponse"}
	)
	public static class HttpJspPageServiceHook extends RASPMethodAdvice {

		public RASPHookResult<?> onMethodEnter() {
			return onRequestEnter(this);
		}

		public RASPHookResult<?> onMethodExit() {
			return onRequestExit(this);
		}

	}

}
