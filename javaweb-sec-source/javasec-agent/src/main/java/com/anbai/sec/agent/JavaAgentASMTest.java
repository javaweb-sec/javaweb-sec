package com.anbai.sec.agent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class JavaAgentASMTest {

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



				}

				return classfileBuffer;
			}
		}, true);// 第二个参数true表示是否允许Agent Retransform，需配合MANIFEST.MF中的Can-Retransform-Classes: true配置
	}

}
