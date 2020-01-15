package com.anbai.sec.proxy;

import java.io.File;
import java.lang.reflect.Proxy;
import java.util.Arrays;

/**
 * Creator: yz
 * Date: 2020/1/14
 */
public class FileSystemProxyTest {

	public static void main(String[] args) {
		// 创建UnixFileSystem类实例
		FileSystem fileSystem = new UnixFileSystem();

		// 使用JDK动态代理生成FileSystem动态代理类实例
		FileSystem proxyInstance = (FileSystem) Proxy.newProxyInstance(
				FileSystem.class.getClassLoader(),// 指定动态代理类的类加载器
				new Class[]{FileSystem.class}, // 定义动态代理生成的类实现的接口
				new JDKInvocationHandler(fileSystem)// 动态代理处理类
		);

		System.out.println("动态代理生成的类名:" + proxyInstance.getClass());
		System.out.println("----------------------------------------------------------------------------------------");
		System.out.println("动态代理生成的类名toString:" + proxyInstance.toString());
		System.out.println("----------------------------------------------------------------------------------------");

		// 使用动态代理的方式UnixFileSystem方法
		String[] files = proxyInstance.list(new File("."));

		System.out.println("----------------------------------------------------------------------------------------");
		System.out.println("UnixFileSystem.list方法执行结果:" + Arrays.toString(files));
		System.out.println("----------------------------------------------------------------------------------------");

		boolean isFileSystem     = proxyInstance instanceof FileSystem;
		boolean isUnixFileSystem = proxyInstance instanceof UnixFileSystem;

		System.out.println("动态代理类[" + proxyInstance.getClass() + "]是否是FileSystem类的实例:" + isFileSystem);
		System.out.println("----------------------------------------------------------------------------------------");
		System.out.println("动态代理类[" + proxyInstance.getClass() + "]是否是UnixFileSystem类的实例:" + isUnixFileSystem);
		System.out.println("----------------------------------------------------------------------------------------");
	}

}
