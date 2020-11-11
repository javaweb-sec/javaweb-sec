/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

/**
 * Hook点处理结果
 * Creator: yz
 * Date: 2019-06-24
 */
public enum RASPHookHandlerType {

	RETURN,// 直接返回什么都不做
	THROW, // 抛出异常
	REPLACE_OR_BLOCK // 阻断或替换值

}
