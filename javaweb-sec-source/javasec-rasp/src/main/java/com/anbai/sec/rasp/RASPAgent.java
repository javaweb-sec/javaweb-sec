package com.anbai.sec.rasp;

import com.anbai.sec.rasp.commons.RASPAgentCache;
import com.anbai.sec.rasp.commons.RASPClassFileTransformer;
import com.anbai.sec.rasp.commons.RASPClassHookConfig;
import com.anbai.sec.rasp.commons.RASPReTransformClass;
import org.javaweb.utils.IOUtils;

import java.io.File;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;

import static com.anbai.sec.rasp.commons.RASPConstants.*;
import static com.anbai.sec.rasp.commons.RASPHookLoader.*;

public class RASPAgent {

	private static RASPAgentCache agentCache;

	/**
	 * Java Agent模式入口
	 *
	 * @param args 命令参数
	 * @param inst Instrumentation
	 */
	public static void premain(String args, Instrumentation inst) {
		loadAgent(args, inst);
	}

	/**
	 * Java Attach模式入口
	 *
	 * @param args 命令参数
	 * @param inst Instrumentation
	 */
	public static void agentmain(String args, Instrumentation inst) {
		loadAgent(args, inst);
	}

	/**
	 * 输出Agent使用示例
	 *
	 * @param vm VirtualMachine
	 */
	private static void printUsage(RASPVirtualMachineLoader vm) {
		System.out.println(AGENT_NAME + " (Java Agent)");
		System.out.println("示例(Usage)：java -jar " + AGENT_LOADER_FILE_NAME + " [Options]");
		System.out.println("  1) detach [Java PID]");
		System.out.println("  2) attach [Java PID]");
		System.out.println();
		System.out.println("例如(EXAMPLES):");
		System.out.println("  java -jar " + AGENT_LOADER_FILE_NAME + " attach 10001");
		System.out.println("  java -jar " + AGENT_LOADER_FILE_NAME + " detach 10001");
		System.out.println();
		System.out.println("当前运行的JVM进程列表:");

		try {
			Map<String, String> processMap = vm.listJVMPID();

			for (String processID : processMap.keySet()) {
				String name = processMap.get(processID);
				System.out.println("PID:" + processID + "\tProcessName:" + ("".equals(name) ? "NONE" : name));
			}
		} catch (Exception e) {
			System.out.println(AGENT_NAME + "获取JVM进程异常:" + e);
			e.printStackTrace();
		}
	}

	/**
	 * 获取Agent URL路径
	 *
	 * @return Agent URL路径
	 */
	private static URL getLoaderFileURL() {
		return RASPAgent.class.getProtectionDomain().getCodeSource().getLocation();
	}

	/**
	 * 获取Agent jar文件
	 *
	 * @return Agent jar文件
	 */
	public static File getLoaderFile() {
		return new File(getLoaderFileURL().getFile());
	}

	/**
	 * 附加Agent到JVM进程
	 */
	public static void attachJVM(String processID, String args, RASPVirtualMachineLoader loader) {
		try {
			// 获取Agent jar的URL地址
			URL loaderFileURL = getLoaderFileURL();

			// 附加进程
			Object vm = loader.attach(processID);

			loader.loadAgent(vm, new File(loaderFileURL.toURI()).getAbsolutePath(), args);
			loader.detach(vm);
		} catch (Exception e) {
			System.out.println("附加" + AGENT_NAME + "到JVM异常: " + e);
			e.printStackTrace();
		}
	}

	private static synchronized void loadAgent(String arg, final Instrumentation inst) {
		String[] args = arg != null ? arg.split("\\s+") : new String[0];

		if (args.length > 0) {
			// 处理灵蜥Agent卸载事件
			if ("detach".equalsIgnoreCase(args[0])) {
				detachAgent();
				return;
			} else if (agentCache != null) {
				// 处理重复attach问题
				System.out.println("检测到" + AGENT_NAME + "已经存在，请勿重复安装!");
				return;
			}
		}

		try {
			if (agentCache == null) {
				// 输出Logo信息
				printLogo();

//				JarFile agentJarFile = new JarFile(new File("/Users/yz/IdeaProjects/javaweb-sec/javaweb-sec-source/javasec-rasp/target/javasec-rasp.jar"));
				JarFile agentJarFile = new JarFile(getLoaderFile());

				// 将Agent添加到BootstrapClassLoader
				inst.appendToBootstrapClassLoaderSearch(agentJarFile);

				// 初始化Hook配置
				Set<RASPClassHookConfig> hookConfigs = loadHooks(agentJarFile);

				// 获取所有的reTransform配置
				Set<RASPReTransformClass> reTransformConfigs = getReTransformConfigs(hookConfigs);

				// 创建ClassFileTransformer
				ClassFileTransformer classFileTransformer = new RASPClassFileTransformer(hookConfigs);

				// 初始化Agent缓存
				agentCache = new RASPAgentCache(inst, classFileTransformer);

				// 注册Transformer
				inst.addTransformer(agentCache.getTransformer(), true);

				// 设置需要reTransform的类
				setReTransformClasses(inst, reTransformConfigs, agentCache);
			}
		} catch (Exception e) {
			new RuntimeException("Agent初始化异常：" + e, e).printStackTrace();
		}
	}

	/**
	 * 卸载灵蜥Agent
	 */
	private static synchronized void detachAgent() {

	}

	/**
	 * 打印RASP Logo
	 */
	private static void printLogo() {
		InputStream in = ClassLoader.getSystemResourceAsStream("banner.txt");

		try {
			if (in != null) {
				String content = IOUtils.inputStreamToString(in);

				System.out.println(content + "\t[" + AGENT_NAME + " " + AGENT_VERSION + "]");
			}
		} catch (Exception e) {
			new RuntimeException("读取banner信息异常：" + e, e).printStackTrace();
		}
	}

	public static void main(String[] args) {
		RASPVirtualMachineLoader vm = new RASPVirtualMachineLoader();

		if (args.length == 0) {
			printUsage(vm);
			return;
		}

		try {
			if ("attach".equalsIgnoreCase(args[0]) || "detach".equalsIgnoreCase(args[0])) {
				attachJVM(args[1].trim(), args[0], vm);
			} else {
				printUsage(vm);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
