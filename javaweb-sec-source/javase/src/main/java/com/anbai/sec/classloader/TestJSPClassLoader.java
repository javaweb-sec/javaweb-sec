package com.anbai.sec.classloader;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;

import java.io.File;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

public class TestJSPClassLoader {

	/**
	 * 缓存JSP文件和类加载，刚jsp文件修改后直接替换类加载器实现JSP类字节码热加载
	 */
	private final Map<File, JSPClassLoader> jspClassLoaderMap = new HashMap<File, JSPClassLoader>();

	/**
	 * 创建用于测试的test.jsp类字节码，类代码如下：
	 * <pre>
	 * package com.anbai.sec.classloader;
	 *
	 * public class test_jsp {
	 *     public void _jspService() {
	 *         System.out.println("Hello...");
	 *     }
	 * }
	 * </pre>
	 *
	 * @param className 类名
	 * @param content   用于测试的输出内容，如：Hello...
	 * @return test_java类字节码
	 * @throws Exception 创建异常
	 */
	public static byte[] createTestJSPClass(String className, String content) throws Exception {
		// 使用Javassist创建类字节码
		ClassPool classPool = ClassPool.getDefault();

		// 创建一个类，如：com.anbai.sec.classloader.test_jsp
		CtClass ctServletClass = classPool.makeClass(className);

		// 创建_jspService方法
		CtMethod ctMethod = new CtMethod(CtClass.voidType, "_jspService", new CtClass[]{}, ctServletClass);
		ctMethod.setModifiers(Modifier.PUBLIC);

		// 写入hello方法代码
		ctMethod.setBody("System.out.println(\"" + content + "\");");

		// 将hello方法添加到类中
		ctServletClass.addMethod(ctMethod);

		// 生成类字节码
		byte[] bytes = ctServletClass.toBytecode();

		// 释放资源
		ctServletClass.detach();

		return bytes;
	}

	/**
	 * 检测jsp文件是否改变，如果发生了修改就重新编译jsp并更新该jsp类字节码
	 *
	 * @param jspFile   JSP文件对象，因为是模拟的jsp文件所以这个文件不需要存在
	 * @param className 类名
	 * @param bytes     类字节码
	 * @param parent    JSP的父类加载
	 */
	public JSPClassLoader getJSPFileClassLoader(File jspFile, String className, byte[] bytes, ClassLoader parent) {
		JSPClassLoader jspClassLoader = this.jspClassLoaderMap.get(jspFile);

		// 模拟第一次访问test.jsp时jspClassLoader是空的，因此需要创建
		if (jspClassLoader == null) {
			jspClassLoader = new JSPClassLoader(parent);
			jspClassLoader.createClass(className, bytes);

			// 缓存JSP文件和所使用的类加载器
			this.jspClassLoaderMap.put(jspFile, jspClassLoader);

			return jspClassLoader;
		}

		// 模拟第二次访问test.jsp，这个时候内容发生了修改，这里实际上应该检测文件的最后修改时间是否相当，
		// 而不是检测是否是0，因为当jspFile不存在的时候返回值是0，所以这里假设0表示这个文件被修改了，
		// 那么需要热加载该类字节码到类加载器。
		if (jspFile.lastModified() == 0) {
			jspClassLoader = new JSPClassLoader(parent);
			jspClassLoader.createClass(className, bytes);

			// 缓存JSP文件和所使用的类加载器
			this.jspClassLoaderMap.put(jspFile, jspClassLoader);
			return jspClassLoader;
		}

		return null;
	}

	/**
	 * 使用动态的类加载器调用test_jsp#_jspService方法
	 *
	 * @param jspFile   JSP文件对象，因为是模拟的jsp文件所以这个文件不需要存在
	 * @param className 类名
	 * @param bytes     类字节码
	 * @param parent    JSP的父类加载
	 */
	public void invokeJSPServiceMethod(File jspFile, String className, byte[] bytes, ClassLoader parent) {
		JSPClassLoader jspClassLoader = getJSPFileClassLoader(jspFile, className, bytes, parent);

		try {
			// 加载com.anbai.sec.classloader.test_jsp类
			Class<?> jspClass = jspClassLoader.loadClass(className);

			// 创建test_jsp类实例
			Object jspInstance = jspClass.newInstance();

			// 获取test_jsp#_jspService方法
			Method jspServiceMethod = jspClass.getMethod("_jspService");

			// 调用_jspService方法
			jspServiceMethod.invoke(jspInstance);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws Exception {
		TestJSPClassLoader test = new TestJSPClassLoader();

		String      className   = "com.anbai.sec.classloader.test_jsp";
		File        jspFile     = new File("/data/test.jsp");
		ClassLoader classLoader = ClassLoader.getSystemClassLoader();

		// 模拟第一次访问test.jsp文件自动生成test_jsp.java
		byte[] testJSPClass01 = createTestJSPClass(className, "Hello...");

		test.invokeJSPServiceMethod(jspFile, className, testJSPClass01, classLoader);

		// 模拟修改了test.jsp文件，热加载修改后的test_jsp.class
		byte[] testJSPClass02 = createTestJSPClass(className, "World...");
		test.invokeJSPServiceMethod(jspFile, className, testJSPClass02, classLoader);
	}

	/**
	 * JSP类加载器
	 */
	static class JSPClassLoader extends ClassLoader {

		public JSPClassLoader(ClassLoader parent) {
			super(parent);
		}

		/**
		 * 创建类
		 *
		 * @param className 类名
		 * @param bytes     类字节码
		 */
		public void createClass(String className, byte[] bytes) {
			defineClass(className, bytes, 0, bytes.length);
		}

	}

}
