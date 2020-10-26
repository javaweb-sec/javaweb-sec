# Java 类字节码编辑 - Javassist

Javassist是一个开源的分析、编辑和创建Java字节码的类库。相比ASM，Javassist更加简单便捷。

```java
package com.anbai.sec.bytecode.javassist;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtField;
import javassist.CtMethod;
import org.javaweb.utils.FileUtils;

import java.io.File;

public class JavassistTest {

	public static void main(String[] args) {
		ClassPool classPool = ClassPool.getDefault();
		CtClass   ctClass   = classPool.makeClass("com.anbai.sec.bytecode.javassist.JavassistHelloWorld");

		try {
			CtField ctField = CtField.make("private static String content = \"Hello world~\";", ctClass);
			ctClass.addField(ctField);

			CtMethod ctMethod = CtMethod.make(
					"public static void main(String[] args) {System.out.println(content);}", ctClass
			);

			ctClass.addMethod(ctMethod);

			File classFilePath = new File(new File(System.getProperty("user.dir"), "javaweb-sec-source/javase/src/main/java/com/anbai/sec/bytecode/javassist/"), "JavassistHelloWorld.class");

			// 使用类CtClass，生成类二进制
			byte[] bytes = ctClass.toBytecode();

			// 将class二进制内容写入到类文件
			FileUtils.writeByteArrayToFile(classFilePath, bytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
```

