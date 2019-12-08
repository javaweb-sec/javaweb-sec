package com.anbai.sec.cmd;

import java.io.File;
import java.lang.reflect.Method;

/**
 * Creator: yz
 * Date: 2019/12/8
 */
public class CommandExecutionTest {

	private static final String COMMAND_CLASS_NAME = "com.anbai.sec.cmd.CommandExecution";

	/**
	 * JDK1.5编译的com.anbai.sec.cmd.CommandExecution类字节码,
	 * 只有一个public static native String exec(String cmd);的方法
	 */
	private static final byte[] COMMAND_CLASS_BYTES = new byte[]{
			-54, -2, -70, -66, 0, 0, 0, 49, 0, 15, 10, 0, 3, 0, 12, 7, 0, 13, 7, 0, 14, 1,
			0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100,
			101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108,
			101, 1, 0, 4, 101, 120, 101, 99, 1, 0, 38, 40, 76, 106, 97, 118, 97, 47, 108, 97,
			110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108,
			97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 1, 0, 10, 83, 111, 117, 114,
			99, 101, 70, 105, 108, 101, 1, 0, 21, 67, 111, 109, 109, 97, 110, 100, 69, 120,
			101, 99, 117, 116, 105, 111, 110, 46, 106, 97, 118, 97, 12, 0, 4, 0, 5, 1, 0, 34,
			99, 111, 109, 47, 97, 110, 98, 97, 105, 47, 115, 101, 99, 47, 99, 109, 100, 47, 67,
			111, 109, 109, 97, 110, 100, 69, 120, 101, 99, 117, 116, 105, 111, 110, 1, 0, 16,
			106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 0, 33, 0,
			2, 0, 3, 0, 0, 0, 0, 0, 2, 0, 1, 0, 4, 0, 5, 0, 1, 0, 6, 0, 0, 0, 29, 0, 1, 0, 1,
			0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 1, 0, 7, 0, 0, 0, 6, 0, 1, 0, 0, 0, 7, 1,
			9, 0, 8, 0, 9, 0, 0, 0, 1, 0, 10, 0, 0, 0, 2, 0, 11
	};

	public static void main(String[] args) {
		String cmd = "ls -la";// 定于需要执行的cmd

		try {
			ClassLoader loader = new ClassLoader(CommandExecutionTest.class.getClassLoader()) {
				@Override
				protected Class<?> findClass(String name) throws ClassNotFoundException {
					try {
						return super.findClass(name);
					} catch (ClassNotFoundException e) {
						return defineClass(COMMAND_CLASS_NAME, COMMAND_CLASS_BYTES, 0, COMMAND_CLASS_BYTES.length);
					}
				}
			};

			// 测试时候换成自己编译好的lib路径
			File libPath = new File("/Users/yz/IdeaProjects/javaweb-sec/javaweb-sec-source/javase/src/main/java/com/anbai/sec/cmd/libcmd.jnilib");

			// load命令执行类
			Class commandClass = loader.loadClass("com.anbai.sec.cmd.CommandExecution");

			// 可以用System.load也加载lib也可以用反射ClassLoader加载,如果loadLibrary0
			// 也被拦截了可以换java.lang.ClassLoader$NativeLibrary类的load方法。
//		    System.load("/Users/yz/IdeaProjects/javaweb-sec/javaweb-sec-source/javase/src/main/java/com/anbai/sec/cmd/libcmd.jnilib/libcmd.jnilib");
			Method loadLibrary0Method = ClassLoader.class.getDeclaredMethod("loadLibrary0", Class.class, File.class);
			loadLibrary0Method.setAccessible(true);
			loadLibrary0Method.invoke(loader, commandClass, libPath);

			String content = (String) commandClass.getMethod("exec", String.class).invoke(null, cmd);
			System.out.println(content);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
