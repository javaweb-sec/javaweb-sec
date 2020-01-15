package com.anbai.sec.proxy;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import static com.anbai.sec.classloader.TestClassLoader.TEST_CLASS_BYTES;
import static com.anbai.sec.classloader.TestClassLoader.TEST_CLASS_NAME;

/**
 * Creator: yz
 * Date: 2020/1/15
 */
public class ProxyDefineClassTest {

	public static void main(String[] args) {
		// 获取系统的类加载器，可以根据具体情况换成一个存在的类加载器
		ClassLoader classLoader = ClassLoader.getSystemClassLoader();

		try {
			// 反射java.lang.reflect.Proxy类获取其中的defineClass0方法
			Method method = Proxy.class.getDeclaredMethod("defineClass0", new Class[]{
					ClassLoader.class, String.class, byte[].class, int.class, int.class
			});

			// 修改方法的访问权限
			method.setAccessible(true);

			// 反射调用java.lang.reflect.Proxy.defineClass0()方法，动态向JVM注册
			// com.anbai.sec.classloader.TestHelloWorld类对象
			Class helloWorldClass = (Class) method.invoke(null, new Object[]{
					classLoader, TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length
			});

			// 输出TestHelloWorld类对象
			System.out.println(helloWorldClass);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
