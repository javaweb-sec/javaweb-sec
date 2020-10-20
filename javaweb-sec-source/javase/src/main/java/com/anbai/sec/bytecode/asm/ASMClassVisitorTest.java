package com.anbai.sec.bytecode.asm;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;

import java.io.IOException;
import java.util.Arrays;

import static org.objectweb.asm.ClassReader.EXPAND_FRAMES;
import static org.objectweb.asm.Opcodes.ASM9;

public class ASMClassVisitorTest {

	public static void main(String[] args) {
		// 定义需要解析的类名称
		String className = "com.anbai.sec.bytecode.TestHelloWorld";

		try {
			// 创建ClassReader对象，用于解析类对象，可以根据类名、二进制、输入流的方式创建
			final ClassReader cr = new ClassReader(className);

			System.out.println(
					"解析类名：" + cr.getClassName() + "，父类：" + cr.getSuperName() +
							"，实现接口：" + Arrays.toString(cr.getInterfaces())
			);

			System.out.println("-----------------------------------------------------------------------------");

			// 使用自定义的ClassVisitor访问者对象，访问该类文件的结构
			cr.accept(new ClassVisitor(ASM9) {
				@Override
				public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
					System.out.println(
							"变量修饰符：" + access + "\t 类名：" + name + "\t 父类名：" + superName +
									"\t 实现的接口：" + Arrays.toString(interfaces)
					);

					System.out.println("-----------------------------------------------------------------------------");

					super.visit(version, access, name, signature, superName, interfaces);
				}

				@Override
				public FieldVisitor visitField(int access, String name, String desc, String signature, Object value) {
					System.out.println(
							"变量修饰符：" + access + "\t 变量名称：" + name + "\t 描述符：" + desc + "\t 默认值：" + value
					);

					return super.visitField(access, name, desc, signature, value);
				}

				@Override
				public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {

					System.out.println(
							"方法修饰符：" + access + "\t 方法名称：" + name + "\t 描述符：" + desc +
									"\t 抛出的异常：" + Arrays.toString(exceptions)
					);

					return super.visitMethod(access, name, desc, signature, exceptions);
				}
			}, EXPAND_FRAMES);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

}
