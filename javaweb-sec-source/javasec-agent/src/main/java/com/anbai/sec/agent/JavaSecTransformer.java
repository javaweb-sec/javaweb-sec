/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * Creator: yz
 * Date: 2020/1/2
 */
public class JavaSecTransformer implements ClassFileTransformer {

	/**
	 * 类文件转换方法，重写transform方法可获取到待加载的类相关信息
	 *
	 * @param loader              定义要转换的类加载器；如果是引导加载器，则为 null
	 * @param className           类名,如:java/lang/Runtime
	 * @param classBeingRedefined 如果是被重定义或重转换触发，则为重定义或重转换的类；如果是类加载，则为 null
	 * @param protectionDomain    要定义或重定义的类的保护域
	 * @param classfileBuffer     类文件格式的输入字节缓冲区（不得修改）
	 * @return 返回一个通过ASM修改后添加了防御代码的字节码byte数组。
	 */
	public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
	                        ProtectionDomain protectionDomain, byte[] classfileBuffer) {

		return classfileBuffer;
	}

}
