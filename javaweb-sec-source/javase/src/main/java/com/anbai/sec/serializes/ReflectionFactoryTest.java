package com.anbai.sec.serializes;

import sun.reflect.ReflectionFactory;

import java.lang.reflect.Constructor;

/**
 * 使用反序列化方式在不调用类构造方法的情况下创建类实例
 * Creator: yz
 * Date: 2019/12/20
 */
public class ReflectionFactoryTest {

	public static void main(String[] args) {
		try {
			// 获取sun.reflect.ReflectionFactory对象
			ReflectionFactory factory = ReflectionFactory.getReflectionFactory();

			// 使用反序列化方式获取DeserializationTest类的构造方法
			Constructor<?> constructor = factory.newConstructorForSerialization(
					DeserializationTest.class, Object.class.getConstructor()
			);

			// 实例化DeserializationTest对象
			System.out.println(constructor.newInstance());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
