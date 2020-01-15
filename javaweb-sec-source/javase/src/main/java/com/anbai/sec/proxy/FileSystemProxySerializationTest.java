package com.anbai.sec.proxy;

import java.io.*;
import java.lang.reflect.Proxy;

/**
 * Creator: yz
 * Date: 2020/1/14
 */
public class FileSystemProxySerializationTest {

	public static void main(String[] args) {
		try {
			// 创建UnixFileSystem类实例
			FileSystem fileSystem = new UnixFileSystem();

			// 使用JDK动态代理生成FileSystem动态代理类实例
			FileSystem proxyInstance = (FileSystem) Proxy.newProxyInstance(
					FileSystem.class.getClassLoader(),// 指定动态代理类的类加载器
					new Class[]{FileSystem.class}, // 定义动态代理生成的类实现的接口
					new JDKInvocationHandler(fileSystem)// 动态代理处理类
			);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			// 创建Java对象序列化输出流对象
			ObjectOutputStream out = new ObjectOutputStream(baos);

			// 序列化动态代理类
			out.writeObject(proxyInstance);
			out.flush();
			out.close();

			// 利用动态代理类生成的二进制数组创建二进制输入流对象用于反序列化操作
			ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

			// 通过反序列化输入流(bais),创建Java对象输入流(ObjectInputStream)对象
			ObjectInputStream in = new ObjectInputStream(bais);

			// 反序列化输入流数据为FileSystem对象
			FileSystem test = (FileSystem) in.readObject();

			System.out.println("反序列化类实例类名:" + test.getClass());
			System.out.println("反序列化类实例toString:" + test.toString());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

	}

}
