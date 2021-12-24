/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.agent;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.net.URL;
import java.security.ProtectionDomain;
import java.util.List;

/**
 * Creator: yz
 * Date: 2020/1/2
 */
public class CrackLicenseAgent {

	/**
	 * 需要被Hook的类
	 */
	private static final String HOOK_CLASS = "com.anbai.sec.agent.CrackLicenseTest";

	/**
	 * Java Agent模式入口
	 *
	 * @param args 命令参数
	 * @param inst Instrumentation
	 */
	public static void premain(String args, final Instrumentation inst) {
		loadAgent(args, inst);
	}

	/**
	 * Java Attach模式入口
	 *
	 * @param args 命令参数
	 * @param inst Instrumentation
	 */
	public static void agentmain(String args, final Instrumentation inst) {
		loadAgent(args, inst);
	}

	public static void main(String[] args) {
		if (args.length == 0) {
			List<VirtualMachineDescriptor> list = VirtualMachine.list();

			for (VirtualMachineDescriptor desc : list) {
				System.out.println("进程ID：" + desc.id() + "，进程名称：" + desc.displayName());
			}

			return;
		}

		// Java进程ID
		String pid = args[0];

		try {
			// 注入到JVM虚拟机进程
			VirtualMachine vm = VirtualMachine.attach(pid);

			// 获取当前Agent的jar包路径
			URL    agentURL  = CrackLicenseAgent.class.getProtectionDomain().getCodeSource().getLocation();
			String agentPath = new File(agentURL.toURI()).getAbsolutePath();

			// 注入Agent到目标JVM
			vm.loadAgent(agentPath);
			vm.detach();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 加载Agent
	 *
	 * @param arg  命令参数
	 * @param inst Instrumentation
	 */
	private static void loadAgent(String arg, final Instrumentation inst) {
		// 创建ClassFileTransformer对象
		ClassFileTransformer classFileTransformer = createClassFileTransformer();

		// 添加自定义的Transformer，第二个参数true表示是否允许Agent Retransform，
		// 需配合MANIFEST.MF中的Can-Retransform-Classes: true配置
		inst.addTransformer(classFileTransformer, true);

		// 获取所有已经被JVM加载的类对象
		Class<?>[] loadedClass = inst.getAllLoadedClasses();

		for (Class<?> clazz : loadedClass) {
			String className = clazz.getName();

			if (inst.isModifiableClass(clazz)) {
				// 使用Agent重新加载HelloWorld类的字节码
				if (className.equals(HOOK_CLASS)) {
					try {
						inst.retransformClasses(clazz);
					} catch (UnmodifiableClassException e) {
						e.printStackTrace();
					}
				}
			}
		}
	}

	private static ClassFileTransformer createClassFileTransformer() {
		return new ClassFileTransformer() {

			/**
			 * 类文件转换方法，重写transform方法可获取到待加载的类相关信息
			 *
			 * @param loader              定义要转换的类加载器；如果是引导加载器，则为 null
			 * @param className           类名,如:java/lang/Runtime
			 * @param classBeingRedefined 如果是被重定义或重转换触发，则为重定义或重转换的类；如果是类加载，则为 null
			 * @param protectionDomain    要定义或重定义的类的保护域
			 * @param classfileBuffer     类文件格式的输入字节缓冲区（不得修改）
			 * @return 字节码byte数组。
			 */
			@Override
			public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
			                        ProtectionDomain protectionDomain, byte[] classfileBuffer) {

				// 将目录路径替换成Java类名
				className = className.replace("/", ".");

				// 只处理com.anbai.sec.agent.CrackLicenseTest类的字节码
				if (className.equals(HOOK_CLASS)) {
					try {
						ClassPool classPool = ClassPool.getDefault();

						// 使用javassist将类二进制解析成CtClass对象
						CtClass ctClass = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));

						// 使用CtClass对象获取checkExpiry方法，类似于Java反射机制的clazz.getDeclaredMethod(xxx)
						CtMethod ctMethod = ctClass.getDeclaredMethod(
								"checkExpiry", new CtClass[]{classPool.getCtClass("java.lang.String")}
						);

						// 在checkExpiry方法执行前插入输出License到期时间代码
						ctMethod.insertBefore("System.out.println(\"License到期时间：\" + $1);");

						// 修改checkExpiry方法的返回值，将授权过期改为未过期
						ctMethod.insertAfter("return false;");

						// 修改后的类字节码
						classfileBuffer = ctClass.toBytecode();

						File dir = new File(System.getProperty("user.dir"), "/src/test/java/com/anbai/sec/agent/");

						if (!dir.exists() && dir.mkdirs()) {
							System.out.println("已创建DumpClass目录：" + dir.getAbsolutePath());
						}

						File classFilePath = new File(dir, "CrackLicenseTest.class");

						// 写入修改后的字节码到class文件
						FileOutputStream fos = new FileOutputStream(classFilePath);
						fos.write(classfileBuffer);
						fos.flush();
						fos.close();
					} catch (Exception e) {
						e.printStackTrace();
					}
				}

				return classfileBuffer;
			}
		};
	}

}
