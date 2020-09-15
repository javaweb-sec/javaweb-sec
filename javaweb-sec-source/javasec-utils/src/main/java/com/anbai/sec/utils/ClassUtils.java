package com.anbai.sec.utils;

import org.objectweb.asm.ClassReader;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

public class ClassUtils {

	/**
	 * 获取一个类的所有父类和实现的接口
	 *
	 * @param className
	 * @param classLoader
	 * @return
	 */
	public static Set<String> getSuperClassListByAsm(String className, ClassLoader classLoader) {
		Set<String> superClassList  = new LinkedHashSet<String>();
		String      objectClassName = Object.class.getName();

		try {
			getSuperClassListByAsm(className, classLoader, superClassList);

			// 把Object的位置放到最后,方便父类检测
			for (Iterator<String> it = superClassList.iterator(); it.hasNext(); ) {
				String name = it.next();

				if (objectClassName.equals(name)) {
					it.remove();
				}
			}

			superClassList.add(objectClassName);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return superClassList;
	}

	/**
	 * 获取一个类的所有父类和实现的接口
	 *
	 * @param className
	 * @param loader
	 * @param superClassList
	 */
	public static void getSuperClassListByAsm(String className, ClassLoader loader, Set<String> superClassList) {
		if (className != null && loader != null) {
			superClassList.add(className);
			byte[] classBytes = getClassBytes(className, loader);

			// TODO: 需要找出为什么无法获取class文件，IDEA Debug Agent类无法获取
			// 忽略无法找到类字节码的class
			if (classBytes != null) {
				ClassReader classReader = new ClassReader(classBytes);

				String   superClass = classReader.getSuperName();// 父类
				String[] interfaces = classReader.getInterfaces();// 父接口

				List<String> ls = new ArrayList<String>();

				// 添加父类
				if (superClass != null) {
					ls.add(superClass);
				}

				// 添加父类的所有接口
				for (String clazz : interfaces) {
					ls.add(clazz);
				}

				// 遍历所有父类和接口
				for (String clazz : ls) {
					getSuperClassListByAsm(toJavaName(clazz), loader, superClassList);
				}
			}
		}
	}

	/**
	 * 查找类对象，获取类字节码
	 *
	 * @param className
	 * @param classLoader
	 * @return
	 */
	public static byte[] getClassBytes(String className, ClassLoader classLoader) {
		InputStream in = null;

		try {
			String classRes = toAsmClassName(className) + ".class";

			in = ClassLoader.getSystemResourceAsStream(classRes);

			if (in == null) {
				in = classLoader.getResourceAsStream(classRes);
			}

			if (in != null) {
				return org.apache.commons.io.IOUtils.toByteArray(in);
			}

			return null;
		} catch (IOException e) {
			return null;
		} finally {
			org.apache.commons.io.IOUtils.closeQuietly(in);
		}
	}

	/**
	 * 获取用于ASM调用的类名称
	 *
	 * @param clazz
	 * @return
	 */
	public static String toAsmClassName(Class clazz) {
		return clazz.getName().replace(".", "/");
	}

	/**
	 * 获取用于ASM调用的类名称
	 *
	 * @param className
	 * @return
	 */
	public static String toAsmClassName(String className) {
		return className.replace(".", "/");
	}

	/**
	 * 转换成Java内部命名方式
	 *
	 * @param className
	 * @return
	 */
	public static String toJavaName(String className) {
		return className.replace("/", ".");
	}

}
