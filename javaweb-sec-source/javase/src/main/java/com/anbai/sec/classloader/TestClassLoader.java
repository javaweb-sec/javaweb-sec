package com.anbai.sec.classloader;

import java.lang.reflect.Method;

/**
 * Creator: yz
 * Date: 2019/12/17
 */
public class TestClassLoader extends ClassLoader {

	// TestHelloWorld类名
	public static String TEST_CLASS_NAME = "com.anbai.sec.classloader.TestHelloWorld";

	// TestHelloWorld类字节码
	public static byte[] TEST_CLASS_BYTES = new byte[]{
			-54, -2, -70, -66, 0, 0, 0, 51, 0, 17, 10, 0, 4, 0, 13, 8, 0, 14, 7, 0, 15, 7, 0,
			16, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100,
			101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101,
			1, 0, 5, 104, 101, 108, 108, 111, 1, 0, 20, 40, 41, 76, 106, 97, 118, 97, 47, 108,
			97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 1, 0, 10, 83, 111, 117, 114, 99,
			101, 70, 105, 108, 101, 1, 0, 19, 84, 101, 115, 116, 72, 101, 108, 108, 111, 87, 111,
			114, 108, 100, 46, 106, 97, 118, 97, 12, 0, 5, 0, 6, 1, 0, 12, 72, 101, 108, 108, 111,
			32, 87, 111, 114, 108, 100, 126, 1, 0, 40, 99, 111, 109, 47, 97, 110, 98, 97, 105, 47,
			115, 101, 99, 47, 99, 108, 97, 115, 115, 108, 111, 97, 100, 101, 114, 47, 84, 101, 115,
			116, 72, 101, 108, 108, 111, 87, 111, 114, 108, 100, 1, 0, 16, 106, 97, 118, 97, 47, 108,
			97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 0, 33, 0, 3, 0, 4, 0, 0, 0, 0, 0, 2, 0, 1,
			0, 5, 0, 6, 0, 1, 0, 7, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0,
			1, 0, 8, 0, 0, 0, 6, 0, 1, 0, 0, 0, 7, 0, 1, 0, 9, 0, 10, 0, 1, 0, 7, 0, 0, 0, 27, 0, 1,
			0, 1, 0, 0, 0, 3, 18, 2, -80, 0, 0, 0, 1, 0, 8, 0, 0, 0, 6, 0, 1, 0, 0, 0, 10, 0, 1, 0, 11,
			0, 0, 0, 2, 0, 12
	};

	@Override
	public Class<?> findClass(String name) throws ClassNotFoundException {
		// 只处理TestHelloWorld类
		if (name.equals(TEST_CLASS_NAME)) {
			// 调用JVM的native方法定义TestHelloWorld类
			return defineClass(TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length);
		}

		return super.findClass(name);
	}

	/**
	 * 使用自定义类加载器加载TestHelloWorld类字节码并调用hello方法示例，等价于如下代码：
	 * <p>
	 *
	 * </p>
	 *
	 * @param args
	 */
	public static void main(String[] args) {
		// 创建自定义的类加载器
		TestClassLoader loader = new TestClassLoader();

		try {
			// 使用自定义的类加载器加载TestHelloWorld类
			Class testClass = loader.loadClass(TEST_CLASS_NAME);

			// 反射创建TestHelloWorld类，等价于 TestHelloWorld t = new TestHelloWorld();
			Object testInstance = testClass.newInstance();

			// 反射获取hello方法
			Method method = testInstance.getClass().getMethod("hello");

			// 反射调用hello方法,等价于 String str = t.hello();
			String str = (String) method.invoke(testInstance);

			System.out.println(str);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
