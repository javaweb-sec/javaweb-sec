/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import java.util.regex.Pattern;

/**
 * 灵蜥全局常量定义
 */
public class RASPConstants {

	/**
	 * 定义Agent包名前缀
	 */
	public static final String AGENT_PACKAGE_PREFIX = "com.anbai.sec.rasp.";

	/**
	 * 定义Agent名称
	 */
	public static final String AGENT_NAME = "JavaSec RASP";

	/**
	 * 定义Agent版本
	 */
	public static final String AGENT_VERSION = "1.0.0";

	/**
	 * 定义Agent loader文件名称
	 */
	public static final String AGENT_LOADER_FILE_NAME = "javasec-rasp.jar";

	/**
	 * 正则表达式多行忽略大小写匹配
	 */
	public static final int MULTIPLE_LINE_CASE_INSENSITIVE = Pattern.DOTALL | Pattern.CASE_INSENSITIVE;

	/**
	 * 默认不需要ASM处理的Java包或类名称
	 */
	public final static String DEFAULT_PROTECTED_PACKAGE_REGEXP = "" +
			"(java\\.(security|util\\.jar)\\.|" +
			"java\\.lang\\.(invoke|ref|concurrent|instrument)|" +
			"java\\.lang\\.(Object|String|Shutdown|ThreadLocal)$|" +
			"javax\\.crypto|sun\\.(security|misc)|" +
			AGENT_PACKAGE_PREFIX.replace(".", "\\.") + "|" +
			"org\\.apache\\.commons\\.(io|lang|logging|configuration)\\.|" +
			"org\\.objectweb\\.asm\\.|com\\.google\\.gson\\.|" +
			"\\$\\$(FastClassBySpringCGLIB|Lambda|EnhancerBySpringCGLIB)\\$)";

	public final static Pattern PROTECTED_PACKAGE_PATTERN = Pattern.compile(DEFAULT_PROTECTED_PACKAGE_REGEXP);

	/**
	 * 抓取日志
	 */
	public static final int RASP_FETCH_LOG = 0;

	/**
	 * 写日志
	 */
	public static final int RASP_WRITE_LOG = 1;

	/**
	 * 状态：成功
	 */
	public static final String SYS_STATUS_SUCCESS = "1";

	/**
	 * 扫描结束
	 */
	public static final int SYS_API_SCAN_FINISH = 2;

	/**
	 * 获取服务器信息
	 */
	public static final String SERVER_INFO = "info";

	/**
	 * 获取服务器版本号
	 */
	public static final String SERVER_VERSION = "1";

	/**
	 * 获取服务器实时内存信息
	 */
	public static final String SERVER_MEMORY = "2";

	/**
	 * 类构造方法
	 */
	public static final String CONSTRUCTOR_INIT = "<init>";

}