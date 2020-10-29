package com.anbai.sec.bytecode.asm;

import org.javaweb.utils.FileUtils;
import org.javaweb.utils.HexUtils;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;

public class TestASMHelloWorldDump implements Opcodes {

	private static final String CLASS_NAME = "com.anbai.sec.classloader.TestASMHelloWorld";

	private static final String CLASS_NAME_ASM = "com/anbai/sec/classloader/TestASMHelloWorld";

	public static byte[] dump() throws Exception {
		// 创建ClassWriter，用于生成类字节码
		ClassWriter cw = new ClassWriter(0);

		// 创建MethodVisitor
		MethodVisitor mv;

		// 创建一个字节码版本为JDK1.7的com.anbai.sec.classloader.TestASMHelloWorld类
		cw.visit(V1_7, ACC_PUBLIC + ACC_SUPER, CLASS_NAME_ASM, null, "java/lang/Object", null);

		// 设置源码文件名
		cw.visitSource("TestHelloWorld.java", null);

		// 创建一个空的构造方法，
		// public TestASMHelloWorld() {
		// }
		{
			mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
			mv.visitCode();
			Label l0 = new Label();
			mv.visitLabel(l0);
			mv.visitLineNumber(5, l0);
			mv.visitVarInsn(ALOAD, 0);
			mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
			mv.visitInsn(RETURN);
			Label l1 = new Label();
			mv.visitLabel(l1);
			mv.visitLocalVariable("this", "L" + CLASS_NAME_ASM + ";", null, l0, l1, 0);
			mv.visitMaxs(1, 1);
			mv.visitEnd();
		}

		// 创建一个hello方法，
		// public static String hello() {
		//     return "Hello World~";
		// }
		{
			mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "hello", "()Ljava/lang/String;", null, null);
			mv.visitCode();
			Label l0 = new Label();
			mv.visitLabel(l0);
			mv.visitLineNumber(8, l0);
			mv.visitLdcInsn("Hello World~");
			mv.visitInsn(ARETURN);
			mv.visitMaxs(1, 0);
			mv.visitEnd();
		}

		cw.visitEnd();

		return cw.toByteArray();
	}

	public static void main(String[] args) throws Exception {
		final byte[] classBytes = dump();

		// 输出ASM生成的TestASMHelloWorld类HEX
		System.out.println(new String(HexUtils.hexDump(classBytes)));

		// 创建自定义类加载器，加载ASM创建的类字节码到JVM
		ClassLoader classLoader = new ClassLoader(TestASMHelloWorldDump.class.getClassLoader()) {
			@Override
			protected Class<?> findClass(String name) {
				try {
					return super.findClass(name);
				} catch (ClassNotFoundException e) {
					return defineClass(CLASS_NAME, classBytes, 0, classBytes.length);
				}
			}
		};

		System.out.println("-----------------------------------------------------------------------------");

		// 反射调用通过ASM生成的TestASMHelloWorld类的hello方法，输出返回值
		System.out.println("hello方法执行结果：" + classLoader.loadClass(CLASS_NAME).getMethod("hello").invoke(null));

		File classFilePath = new File(new File(System.getProperty("user.dir"), "javaweb-sec-source/javase/src/main/java/com/anbai/sec/bytecode/asm/"), "TestASMHelloWorld.class");

		// 写入修改后的字节码到class文件
		FileUtils.writeByteArrayToFile(classFilePath, classBytes);
	}

}