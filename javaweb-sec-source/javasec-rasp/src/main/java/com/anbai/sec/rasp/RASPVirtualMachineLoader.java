/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 创建VirtualMachine加载器,加载JVM tools.jar
 * Creator: yz
 * Date: 2019-07-19
 */
public class RASPVirtualMachineLoader {

	private Class virtualMachineClass;

	public RASPVirtualMachineLoader() {
		String virtualMachineName = "com.sun.tools.attach.VirtualMachine";

		try {
			virtualMachineClass = Class.forName(virtualMachineName);
		} catch (ClassNotFoundException e) {
			File toolsJar = RASPVirtualMachineLoader.getJDKToolsJar();

			try {
				URL[] urls = new URL[]{toolsJar.toURI().toURL()};
				virtualMachineClass = new URLClassLoader(urls).loadClass(virtualMachineName);
			} catch (Exception ex) {
				System.out.println("Agent加载tools.jar异常: " + e);
				ex.printStackTrace();
			}
		}
	}

	/**
	 * 获取JDK安装目录
	 *
	 * @return 获取lib/tools.jar文件路径
	 */
	public static File getJDKToolsJar() {
		// 读取环境变量中的JAVA_HOME
		String javaHome = System.getenv().get("JAVA_HOME");
		File   jarFile  = null;

		if (javaHome != null) {
			jarFile = new File(javaHome);
		} else {
			jarFile = new File(System.getProperty("java.home"));
		}

		File toolsJar = new File(jarFile + "/lib/", "tools.jar");

		// 可能获取到的JAVA_HOME是jre,跳转到jre的父级查找是否安装了JDK
		if (!toolsJar.exists()) {
			toolsJar = new File(toolsJar.getParentFile().getParentFile() + "/lib/", "tools.jar");
		}

		if (toolsJar.exists()) {
			return toolsJar;
		} else {
			toolsJar = new File(jarFile + "/Classes/", "classes.jar");

			if (toolsJar.exists()) {
				return toolsJar;
			}
		}

		throw new RuntimeException("Agent不能够加载JVM tools.jar,请确认已配置好\"JAVA_HOME\"环境变量。");
	}

	/**
	 * 获取本机所有的JVM进程ID
	 *
	 * @return 进程JVM 进程ID Map
	 */
	public Map<String, String> listJVMPID() throws Exception {
		Map<String, String> processMap = new HashMap<String, String>();
		List                list       = (List) virtualMachineClass.getDeclaredMethod("list").invoke(null);

		for (Object p : list) {
			Class  descriptorClass = p.getClass();
			String processId       = (String) descriptorClass.getMethod("id").invoke(p);
			String displayName     = (String) descriptorClass.getMethod("displayName").invoke(p);

			processMap.put(processId, displayName);
		}

		return processMap;
	}

	/**
	 * 附加到JVM 进程
	 *
	 * @param pid 进程ID
	 * @return VirtualMachine
	 * @throws Exception 反射调用异常
	 */
	public Object attach(String pid) throws Exception {
		return virtualMachineClass.getDeclaredMethod("attach", String.class).invoke(null, pid);
	}

	public void detach(Object vm) throws Exception {
		vm.getClass().getDeclaredMethod("detach").invoke(vm);
	}

	/**
	 * 加载Agent文件到JVM
	 *
	 * @param vm        VirtualMachine
	 * @param agentFile Agent jar文件
	 * @param args      Agent参数
	 * @throws Exception 反射调用异常
	 */
	public void loadAgent(Object vm, String agentFile, String args) throws Exception {
		virtualMachineClass.getDeclaredMethod("loadAgent", String.class, String.class).invoke(vm, agentFile, args);
	}

}
