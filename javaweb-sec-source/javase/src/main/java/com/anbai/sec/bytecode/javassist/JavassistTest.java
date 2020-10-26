package com.anbai.sec.bytecode.javassist;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtField;
import javassist.CtMethod;
import org.javaweb.utils.FileUtils;

import java.io.File;

public class JavassistTest {

    public static void main(String[] args) {
        // 创建ClassPool对象
        ClassPool classPool = ClassPool.getDefault();

        // 使用ClassPool创建一个JavassistHelloWorld类
        CtClass ctClass = classPool.makeClass("com.anbai.sec.bytecode.javassist.JavassistHelloWorld");

        try {
            // 创建类成员变量content
            CtField ctField = CtField.make("private static String content = \"Hello world~\";", ctClass);

            // 将成员变量添加到ctClass对象中
            ctClass.addField(ctField);

            // 创建一个主方法并输出content对象值
            CtMethod ctMethod = CtMethod.make(
                    "public static void main(String[] args) {System.out.println(content);}", ctClass
            );

            // 将成员方法添加到ctClass对象中
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