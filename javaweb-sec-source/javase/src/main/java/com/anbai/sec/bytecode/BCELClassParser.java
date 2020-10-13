package com.anbai.sec.bytecode;

import org.apache.bcel.classfile.ClassParser;
import org.apache.bcel.classfile.ConstantPool;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.ConstantPoolGen;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class BCELClassParser {

	public static void main(String[] args) {
		String classFile = "/Users/yz/IdeaProjects/anbai-lingxe-cloud/target/classes/com/tongtech/asdp/cloud/config/RedisConfig.class";

		try {
			int maxStack    = 0;
			int maxLocals   = 0;
			int methodIndex = 0;

			ByteArrayOutputStream out       = new ByteArrayOutputStream();
			JavaClass             javaClass = new ClassParser(classFile).parse();
			String                className = javaClass.getClassName();
			Method[]              methods   = javaClass.getMethods();
			ConstantPool          constants = javaClass.getConstantPool();

			// 创建常量池生成对象
			ConstantPoolGen cpg = new ConstantPoolGen(constants);
//			MethodGen       mg  = new MethodGen(methods[methodIndex], className, cpg);
//
//			mg.setMaxStack(maxStack);
//			mg.setMaxLocals(maxLocals);
//			methods[methodIndex] = mg.getMethod();

			javaClass.setConstantPool(cpg.getFinalConstantPool());

			javaClass.dump(out);

			System.out.println(out.toString());
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

}
