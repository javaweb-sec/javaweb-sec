/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.agent;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.NotFoundException;

import java.io.ByteArrayInputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * Creator: yz
 * Date: 2020/1/2
 */
public class JavaSecHelloWorldAgent {

    /**
     * Java Agent模式入口
     *
     * @param args 命令参数
     * @param inst Agent Instrumentation 实例
     */
    public static void premain(String args, final Instrumentation inst) {
        // 添加自定义的Transformer
        inst.addTransformer(new ClassFileTransformer() {

            /**
             * 类文件转换方法，重写transform方法可获取到待加载的类相关信息
             *
             * @param loader              定义要转换的类加载器；如果是引导加载器，则为 null
             * @param className           类名,如:java/lang/Runtime
             * @param classBeingRedefined 如果是被重定义或重转换触发，则为重定义或重转换的类；如果是类加载，则为 null
             * @param protectionDomain    要定义或重定义的类的保护域
             * @param classfileBuffer     类文件格式的输入字节缓冲区（不得修改）
             * @return 返回一个通过ASM修改后添加了防御代码的字节码byte数组。
             */
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) {

                // 将目录路径替换成Java类名
                className = className.replace("/", ".");

                // 只处理com.anbai.sec.agent.HelloWorld类的字节码
                if (className.equals("com.anbai.sec.agent.HelloWorld")) {
                    try {
                        ClassPool classPool = ClassPool.getDefault();

                        // 使用javassist将类二进制解析成CtClass对象
                        CtClass ctClass = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));

                        // 使用CtClass对象获取main方法，类似于Java反射机制的clazz.getDeclaredMethod(xxx)
                        CtMethod ctMethod = ctClass.getDeclaredMethod(
                                "main", new CtClass[]{classPool.getCtClass("java.lang.String[]")}
                        );

                        // 直接修改main方法的字节码
                        ctMethod.setBody("System.out.println(\"Hello Java Agent!\");");

                        // 将使用javassist修改后的类字节码给JVM加载
                        return ctClass.toBytecode();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                return classfileBuffer;
            }
        }, true);
        // 第二个参数true表示是否允许Agent Retransform，需配合MANIFEST.MF中的Can-Retransform-Classes: true配置
    }

    public static void main(String[] args) {
        ClassPool classPool = ClassPool.getDefault();

        try {
            System.out.println(classPool.getCtClass("java.lang.String[]"));
        } catch (NotFoundException e) {
            e.printStackTrace();
        }
    }

}
