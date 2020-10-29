package com.anbai.sec.bytecode.asm;

import org.javaweb.utils.FileUtils;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.AdviceAdapter;

import java.io.File;
import java.io.IOException;

import static org.objectweb.asm.ClassReader.EXPAND_FRAMES;
import static org.objectweb.asm.Opcodes.ASM9;

public class ASMMethodVisitorTest {

	public static void main(String[] args) {
		// 定义需要解析的类名称
		String className = "com.anbai.sec.bytecode.TestHelloWorld";

		try {
			// 创建ClassReader对象，用于解析类对象，可以根据类名、二进制、输入流的方式创建
			final ClassReader cr = new ClassReader(className);

			// 创建ClassWriter对象，COMPUTE_FRAMES会自动计算max_stack和max_locals
			final ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);

			// 使用自定义的ClassVisitor访问者对象，访问该类文件的结构
			cr.accept(new ClassVisitor(ASM9, cw) {
				@Override
				public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
					if (name.equals("hello")) {
						MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);

						// 创建自定义的MethodVisitor，修改原方法的字节码
						return new AdviceAdapter(api, mv, access, name, desc) {
							int newArgIndex;

							// 获取String的ASM Type对象
							private final Type stringType = Type.getType(String.class);

							@Override
							protected void onMethodEnter() {
								// 输出hello方法的第一个参数，因为hello是非static方法，所以0是this，第一个参数的下标应该是1
								mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
								mv.visitVarInsn(ALOAD, 1);
								mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);

								// 创建一个新的局部变量，newLocal会计算出这个新局部对象的索引位置
								newArgIndex = newLocal(stringType);

								// 压入字符串到栈顶
								mv.visitLdcInsn("javasec.org");

								// 将"javasec.org"字符串压入到新生成的局部变量中，String var2 = "javasec.org";
								storeLocal(newArgIndex, stringType);
							}

							@Override
							protected void onMethodExit(int opcode) {
								dup(); // 复制栈顶的返回值

								// 创建一个新的局部变量，并获取索引位置
								int returnValueIndex = newLocal(stringType);

								// 将栈顶的返回值压入新生成的局部变量中
								storeLocal(returnValueIndex, stringType);

								// 输出hello方法的返回值
								mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
								mv.visitVarInsn(ALOAD, returnValueIndex);
								mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);

								// 压入方法进入(onMethodEnter)时存入到局部变量的var2值到栈顶
								loadLocal(newArgIndex);

								// 返回一个引用类型，即栈顶的var2字符串，return var2;
								// 需要特别注意的是不同数据类型应当使用不同的RETURN指令
								mv.visitInsn(ARETURN);
							}
						};
					}

					return super.visitMethod(access, name, desc, signature, exceptions);
				}
			}, EXPAND_FRAMES);

			File classFilePath = new File(new File(System.getProperty("user.dir"), "javaweb-sec-source/javase/src/main/java/com/anbai/sec/bytecode/"), "TestHelloWorld.class");

			// 修改后的类字节码
			byte[] classBytes = cw.toByteArray();

			// 写入修改后的字节码到class文件
			FileUtils.writeByteArrayToFile(classFilePath, classBytes);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
