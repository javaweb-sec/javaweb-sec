package com.anbai.sec.unsafe;

import sun.misc.Unsafe;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

import static com.anbai.sec.classloader.TestClassLoader.TEST_CLASS_BYTES;
import static com.anbai.sec.classloader.TestClassLoader.TEST_CLASS_NAME;

/**
 * Creator: yz
 * Date: 2019/12/19
 */
public class UnSafeTest {

	private UnSafeTest() {
		// 假设RASP在这个构造方法中插入了Hook代码，我们可以利用Unsafe来创建类实例
		System.out.println("init...");
	}

	public static void main(String[] args) {
		try {
			// 反射获取Unsafe的theUnsafe成员变量
			Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");

			// 反射设置theUnsafe访问权限
			theUnsafeField.setAccessible(true);

			// 反射获取theUnsafe成员变量值
			Unsafe unsafe = (Unsafe) theUnsafeField.get(null);

			// 获取Unsafe无参构造方法
			Constructor constructor = Unsafe.class.getDeclaredConstructor();

			// 修改构造方法访问权限
			constructor.setAccessible(true);

			// 反射创建Unsafe类实例，等价于 Unsafe unsafe1 = new Unsafe();
			Unsafe unsafe1 = (Unsafe) constructor.newInstance();

			System.out.println(unsafe);
			System.out.println(unsafe1);

			// 使用Unsafe创建UnSafeTest类实例
			UnSafeTest test = (UnSafeTest) unsafe1.allocateInstance(UnSafeTest.class);
			System.out.println(test);

			// 使用Unsafe向JVM中注册com.anbai.sec.classloader.TestHelloWorld类
//			Class helloWorldClass = unsafe1.defineClass(TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length);

			// 获取系统的类加载器
			ClassLoader classLoader = ClassLoader.getSystemClassLoader();

			// 创建默认的保护域
			ProtectionDomain domain = new ProtectionDomain(
					new CodeSource(null, (Certificate[]) null), null, classLoader, null
			);

			// 使用Unsafe向JVM中注册com.anbai.sec.classloader.TestHelloWorld类
			Class helloWorldClass = unsafe1.defineClass(
					TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length, classLoader, domain
			);

			System.out.println(helloWorldClass);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
