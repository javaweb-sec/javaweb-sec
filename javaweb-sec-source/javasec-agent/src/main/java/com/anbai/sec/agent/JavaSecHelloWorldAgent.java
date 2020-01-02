/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.agent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Arrays;

/**
 * Creator: yz
 * Date: 2020/1/2
 */
public class JavaSecHelloWorldAgent {

	/**
	 * 替换HelloWorld的输出字符串为"Hello Agent..."，将二进制转换成字符串数组，替换字符串数组并生成新的二进制
	 *
	 * @param className   类名
	 * @param classBuffer 类字节码
	 * @return 替换后的类字节码
	 */
	private static byte[] replaceBytes(String className, byte[] classBuffer) {
		// 将类字节码转换成byte字符串
		String bufferStr = Arrays.toString(classBuffer);
		System.out.println(className + "类替换前的字节码:" + bufferStr);

		bufferStr = bufferStr.replace("[", "").replace("]", "");

		// 查找需要替换的Java二进制内容
		byte[] findBytes = "Hello World...".getBytes();

		// 把搜索的字符串byte转换成byte字符串
		String findStr = Arrays.toString(findBytes).replace("[", "").replace("]", "");

		// 二进制替换后的byte值，注意这个值需要和替换的字符串长度一致，不然会破坏常量池
		byte[] replaceBytes = "Hello Agent...".getBytes();

		// 把替换的字符串byte转换成byte字符串
		String replaceStr = Arrays.toString(replaceBytes).replace("[", "").replace("]", "");

		bufferStr = bufferStr.replace(findStr, replaceStr);

		// 切割替换后的byte字符串
		String[] byteArray = bufferStr.split("\\s*,\\s*");

		// 创建新的byte数组，存储替换后的二进制
		byte[] bytes = new byte[byteArray.length];

		// 将byte字符串转换成byte
		for (int i = 0; i < byteArray.length; i++) {
			bytes[i] = Byte.parseByte(byteArray[i]);
		}

		System.out.println(className + "类替换后的字节码:" + Arrays.toString(bytes));

		// 返回修改后的二进制
		return bytes;
	}

	/**
	 * Java Agent模式入口
	 *
	 * @param args 命令参数
	 * @param inst Agent Instrumentation 实例
	 */
	public static void premain(String args, final Instrumentation inst) {
		// 添加自定义的Transformer
		inst.addTransformer(new ClassFileTransformer() {

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
			@Override
			public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
			                        ProtectionDomain protectionDomain, byte[] classfileBuffer) {

				// 将目录路径替换成Java类名
				className = className.replace("/", ".");

				// 只处理com.anbai.sec.agent.HelloWorld类的字节码
				if (className.equals("com.anbai.sec.agent.HelloWorld")) {
					// 替换HelloWorld的输出字符串
					return replaceBytes(className, classfileBuffer);
				}

				return classfileBuffer;
			}
		}, true);// 第二个参数true表示是否允许Agent Retransform，需配合MANIFEST.MF中的Can-Retransform-Classes: true配置
	}

}
