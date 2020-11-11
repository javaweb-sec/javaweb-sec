/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.exception;

import static com.anbai.sec.rasp.commons.RASPConstants.AGENT_NAME;

/**
 * Creator: yz
 * Date: 2019-07-31
 */
public class RASPHookException extends Exception {

	public RASPHookException(String type) {
		super(String.format(AGENT_NAME + "检测到恶意攻击类型:[%s],您的请求可能包含了恶意攻击行为,请勿尝试非法攻击!", type));
	}

}