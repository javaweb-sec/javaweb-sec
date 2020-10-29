package com.anbai.sec.bytecode.asm;

import org.javaweb.utils.FileUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;

import java.io.File;
import java.io.IOException;

import static org.objectweb.asm.ClassReader.EXPAND_FRAMES;
import static org.objectweb.asm.Opcodes.*;

public class ASMClassWriterTest {

	public static void main(String[] args) {
		// 定义需要解析的类名称
		String className = "com.anbai.sec.bytecode.TestHelloWorld";

		// 定义修改后的类名
		final String newClassName = "JavaSecTestHelloWorld";

		try {
			// 创建ClassReader对象，用于解析类对象，可以根据类名、二进制、输入流的方式创建
			final ClassReader cr = new ClassReader(className);

			// 创建ClassWriter对象
			final ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);

			// 使用自定义的ClassVisitor访问者对象，访问该类文件的结构
			cr.accept(new ClassVisitor(ASM9, cw) {
				@Override
				public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
					super.visit(version, access, newClassName, signature, superName, interfaces);
				}

				@Override
				public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
					// 将"hello"方法名字修改为"hi"
					if (name.equals("hello")) {
						// 修改方法访问修饰符，移除public属性，修改为private
						access = access & ~ACC_PUBLIC | ACC_PRIVATE;

						return super.visitMethod(access, "hi", desc, signature, exceptions);
					}

					return super.visitMethod(access, name, desc, signature, exceptions);
				}
			}, EXPAND_FRAMES);

			File classFilePath = new File(new File(System.getProperty("user.dir"), "javaweb-sec-source/javase/src/main/java/com/anbai/sec/bytecode/asm/"), newClassName + ".class");

			// 修改后的类字节码
			byte[] classBytes = cw.toByteArray();

			// 写入修改后的字节码到class文件
			FileUtils.writeByteArrayToFile(classFilePath, classBytes);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
