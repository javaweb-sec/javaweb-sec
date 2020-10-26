# Java 类字节码编辑 - Javassist

`Javassist`是一个开源的分析、编辑和创建Java字节码的类库；相比ASM，`Javassist`提供了更加简单便捷的API，使用`Javassist`我们可以像写Java代码一样直接插入Java代码片段，让我们不再需要关注Java底层的字节码的和栈操作，仅需要学会如何使用`Javassist`的API即可实现字节码编辑。学习`Javassist`可以阅读官方的入门教程：[Getting Started with Javassist](http://www.javassist.org/tutorial/tutorial.html)。

`Javassist`为我们提供了类似于Java反射机制的API，如：[CtClass](http://www.javassist.org/html/javassist/CtClass.html)、[CtConstructor](http://www.javassist.org/html/javassist/CtConstructor.html)、[CtMethod](http://www.javassist.org/html/javassist/CtMethod.html)、[CtField](http://www.javassist.org/html/javassist/CtField.html)等，使用这些API我们可以实现对一个类文件的动态编辑。



## 动态创建Java类二进制

`Javassist`可以像ASM一样动态的创建出一个类的二进制，不过使用`Javassist`可比ASM简单了不少，假设我们需要生成一个`JavassistHelloWorld`类，代码如下：

```java
package com.anbai.sec.bytecode.javassist;

public class JavassistHelloWorld {

    private static String content = "Hello world~";

    public static void main(String[] args) {
        System.out.println(content);
    }

}
```

**使用Javassist生成类字节码示例：**

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
```

