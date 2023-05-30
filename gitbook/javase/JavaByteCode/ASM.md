# Java 类字节码编辑 - ASM

Java字节码库允许我们通过字节码库的API动态创建或修改Java类、方法、变量等操作而被广泛使用，本节将讲解ASM库的使用。

ASM是一种通用Java字节码操作和分析框架，它可以直接以二进制形式修改一个现有的类或动态生成类文件。ASM的版本更新快（`ASM 9.0`已经支持`JDK 16`）、[性能高](https://asm.ow2.io/performance.html)、功能全，学习成本也相对较高，ASM官方用户手册：[ASM 4.0 A Java bytecode engineering library](https://asm.ow2.io/asm4-guide.pdf)。

ASM提供了三个基于`ClassVisitor API`的核心API，用于生成和转换类：

1. `ClassReader`类用于解析class文件或二进制流；
2. `ClassWriter`类是`ClassVisitor`的子类，用于生成类二进制；
3. `ClassVisitor`是一个抽象类，自定义`ClassVisitor`重写`visitXXX`方法，可获取捕获ASM类结构访问的所有事件；

## ClassReader和ClassVisitor

`ClassReader`类用于解析类字节码，创建`ClassReader`对象可传入类名、类字节码数组或者类输入流对象。

创建完`ClassReader`对象就会触发字节码解析（解析class基础信息，如常量池、接口信息等），所以可以直接通过`ClassReader`对象获取类的基础信息，如下：

```java
// 创建ClassReader对象，用于解析类对象，可以根据类名、二进制、输入流的方式创建
final ClassReader cr = new ClassReader(className);

        System.out.println(
        "解析类名：" + cr.getClassName() + "，父类：" + cr.getSuperName() +
        "，实现接口：" + Arrays.toString(cr.getInterfaces())
        );
```

调用`ClassReader`类的`accpet`方法需要传入自定义的`ClassVisitor`对象，`ClassReader`会按照如下顺序，依次调用该`ClassVisitor`的类方法。

```java
visit
        [ visitSource ] [ visitModule ][ visitNestHost ][ visitPermittedclass ][ visitOuterClass ]
        ( visitAnnotation | visitTypeAnnotation | visitAttribute )*
        ( visitNestMember | visitInnerClass | visitRecordComponent | visitField | visitMethod )*
        visitEnd
```

**ClassVisitor类图：**

![img](https://oss.javasec.org/images/image-20201020185201582.png)



## MethodVisitor和AdviceAdapter

`MethodVisitor`同`ClassVisitor`，重写`MethodVisitor`类方法可获取捕获到对应的`visit`事件，`MethodVisitor`会依次按照如下顺序调用`visit`方法：

```java
( visitParameter )* [ visitAnnotationDefault ] 
  ( visitAnnotation | visitAnnotableParameterCount | visitParameterAnnotation visitTypeAnnotation | visitAttribute )* 
  [ visitCode 
   ( visitFrame | visit<i>X</i>Insn | visitLabel | visitInsnAnnotation | visitTryCatchBlock | visitTryCatchAnnotation | visitLocalVariable | visitLocalVariableAnnotation | visitLineNumber )* 
   visitMaxs 
  ] 
visitEnd
```

`AdviceAdapter`的父类是`GeneratorAdapter`和`LocalVariablesSorter`，在`MethodVisitor`类的基础上封装了非常多的便捷方法，同时还为我们做了非常有必要的计算，所以我们应该尽可能的使用`AdviceAdapter`来修改字节码。

`AdviceAdapter`类实现了一些非常有价值的方法，如：`onMethodEnter`（方法进入时回调方法）、`onMethodExit`（方法退出时回调方法），如果我们自己实现很容易掉进坑里面，因为这两个方法都是根据条件推算出来的。比如我们如果在构造方法的第一行直接插入了我们自己的字节码就可能会发现程序一运行就会崩溃，因为Java语法中限制我们第一行代码必须是`super(xxx)`。

`GeneratorAdapter`封装了一些栈指令操作的方法，如`loadArgArray`方法可以直接获取方法所有参数数组、`invokeStatic`方法可以直接调用类方法、`push`方法可压入各种类型的对象等。

比如`LocalVariablesSorter`类实现了计算本地变量索引位置的方法，如果要在方法中插入新的局部变量就必须计算变量的索引位置，我们必须先判断是否是非静态方法、是否是`long/double`类型的参数（宽类型占两个位），否则计算出的索引位置还是错的。使用`AdviceAdapter`可以直接调用`mv.newLocal(type)`计算出本地变量存储的位置，为我们省去了许多不必要的麻烦。



## 读取类/成员变量/方法信息

为了学习`ClassVisitor`，我们写一个简单的读取类、成员变量、方法信息的一个示例，需要重写`ClassVisitor`类的`visit`、`visitField`和`visitMethod`方法。

**ASM读取类信息示例代码：**

```java
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
```

程序执行后输出：

```java
解析类名：com/anbai/sec/bytecode/TestHelloWorld，父类：java/lang/Object，实现接口：[java/io/Serializable]
-----------------------------------------------------------------------------
变量修饰符：131105     类名：com/anbai/sec/bytecode/TestHelloWorld    父类名：java/lang/Object    实现的接口：[java/io/Serializable]
-----------------------------------------------------------------------------
变量修饰符：26     变量名称：serialVersionUID   描述符：J   默认值：-7366591802115333975
变量修饰符：2  变量名称：id     描述符：J   默认值：null
变量修饰符：2  变量名称：username   描述符：Ljava/lang/String;  默认值：null
变量修饰符：2  变量名称：password   描述符：Ljava/lang/String;  默认值：null
方法修饰符：1  方法名称：<init>     描述符：()V     抛出的异常：null
方法修饰符：1  方法名称：hello  描述符：(Ljava/lang/String;)Ljava/lang/String;  抛出的异常：null
方法修饰符：9  方法名称：main   描述符：([Ljava/lang/String;)V  抛出的异常：null
方法修饰符：1  方法名称：getId  描述符：()J     抛出的异常：null
方法修饰符：1  方法名称：setId  描述符：(J)V    抛出的异常：null
方法修饰符：1  方法名称：getUsername    描述符：()Ljava/lang/String;    抛出的异常：null
方法修饰符：1  方法名称：setUsername    描述符：(Ljava/lang/String;)V   抛出的异常：null
方法修饰符：1  方法名称：getPassword    描述符：()Ljava/lang/String;    抛出的异常：null
方法修饰符：1  方法名称：setPassword    描述符：(Ljava/lang/String;)V   抛出的异常：null
方法修饰符：1  方法名称：toString   描述符：()Ljava/lang/String;    抛出的异常：null
```

通过这个简单的示例，我们可以通过ASM实现遍历一个类的基础信息。

## 修改类名/方法名称/方法修饰符示例

使用`ClassWriter`可以实现类修改功能，使用ASM修改类字节码时如果插入了新的局部变量、字节码，需要重新计算`max_stack`和`max_locals`，否则会导致修改后的类文件无法通过JVM校验。手动计算`max_stack`和`max_locals`是一件比较麻烦的事情，ASM为我们提供了内置的自动计算方式，只需在创建`ClassWriter`的时候传入`COMPUTE_FRAMES`即可：`new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);`

**ASM修改类字节码示例代码：**

```java
package com.anbai.sec.bytecode.asm;

import org.javaweb.utils.FileUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;

import java.io.File;
import java.io.IOException;

import static org.objectweb.asm.ClassReader.EXPAND_FRAMES;
import static org.objectweb.asm.ClassWriter.COMPUTE_FRAMES;
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

            // 创建ClassWriter对象，COMPUTE_FRAMES会自动计算max_stack和max_locals
            final ClassWriter cw = new ClassWriter(cr, COMPUTE_FRAMES);

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
```

修改成功后将会生成一个名为`JavaSecTestHelloWorld.class`的新的class文件，反编译`JavaSecTestHelloWorld`类会发现该类的`hello`方法也已被修改为了`hi`，修饰符已被改为`private`，如下图：

![img](https://oss.javasec.org/images/image-20201021103823611.png)

## 修改类方法字节码

大多数使用ASM库的目的其实是修改类方法的字节码，在原方法执行的前后动态插入新的Java代码，从而实现类似于AOP的功能。修改类方法字节码的典型应用场景如：APM和RASP；APM需要统计和分析每个类方法的执行时间，而RASP需要在Java底层API方法执行之前插入自身的检测代码，从而实现动态拦截恶意攻击。

假设我们需要修改`com.anbai.sec.bytecode.TestHelloWorld`类的hello方法，实现以下两个需求：

1. 在原业务逻辑执行前打印出该方法的参数值；
2. 修改该方法的返回值；

原业务逻辑：

```java
public String hello(String content) {
   String str = "Hello:";
   return str + content;
}
```

修改之后的业务逻辑代码：

```java
public String hello(String content) {
    System.out.println(content);
    String var2 = "javasec.org";
  
    String str = "Hello:";
    String var4 = str + content;
  
    System.out.println(var4);
    return var2;
}
```

借助ASM我们可以实现类方法的字节码编辑。

**修改类方法字节码实现代码：**

```java
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
```

程序执行后会在`com.anbai.sec.bytecode`包下创建一个`TestHelloWorld.class`文件：

![img](https://oss.javasec.org/images/image-20201021174318013.png)

命令行运行`TestHelloWorld`类，可以看到程序执行的逻辑已经被成功修改，输出结果如下：

![img](https://oss.javasec.org/images/image-20201021174453163.png)



## 动态创建Java类二进制

在某些业务场景下我们需要动态一个类来实现一些业务，这个时候就可以使用`ClassWriter`来动态创建出一个Java类的二进制文件，然后通过自定义的类加载器就可以将我们动态生成的类加载到JVM中。假设我们需要生成一个`TestASMHelloWorld`类，代码如下：

**示例TestASMHelloWorld类：**

```java
package com.anbai.sec.classloader;

public class TestASMHelloWorld {
    public static String hello() {
        return "Hello World~";
    }
}
```

**使用ClassWriter生成类字节码示例：**

```java
package com.anbai.sec.bytecode.asm;

import org.javaweb.utils.HexUtils;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

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
   }

}
```

程序执行结果如下：

```bash
0000019F CA FE BA BE 00 00 00 33 00 14 01 00 2B 63 6F 6D .......3....+com
000001AF 2F 61 6E 62 61 69 2F 73 65 63 2F 63 6C 61 73 73 /anbai/sec/class
000001BF 6C 6F 61 64 65 72 2F 54 65 73 74 41 53 4D 48 65 loader/TestASMHe
000001CF 6C 6C 6F 57 6F 72 6C 64 07 00 01 01 00 10 6A 61 lloWorld......ja
000001DF 76 61 2F 6C 61 6E 67 2F 4F 62 6A 65 63 74 07 00 va/lang/Object..
000001EF 03 01 00 13 54 65 73 74 48 65 6C 6C 6F 57 6F 72 ....TestHelloWor
000001FF 6C 64 2E 6A 61 76 61 01 00 06 3C 69 6E 69 74 3E ld.java...<init>
0000020F 01 00 03 28 29 56 0C 00 06 00 07 0A 00 04 00 08 ...()V..........
0000021F 01 00 04 74 68 69 73 01 00 2D 4C 63 6F 6D 2F 61 ...this..-Lcom/a
0000022F 6E 62 61 69 2F 73 65 63 2F 63 6C 61 73 73 6C 6F nbai/sec/classlo
0000023F 61 64 65 72 2F 54 65 73 74 41 53 4D 48 65 6C 6C ader/TestASMHell
0000024F 6F 57 6F 72 6C 64 3B 01 00 05 68 65 6C 6C 6F 01 oWorld;...hello.
0000025F 00 14 28 29 4C 6A 61 76 61 2F 6C 61 6E 67 2F 53 ..()Ljava/lang/S
0000026F 74 72 69 6E 67 3B 01 00 0C 48 65 6C 6C 6F 20 57 tring;...Hello W
0000027F 6F 72 6C 64 7E 08 00 0E 01 00 04 43 6F 64 65 01 orld~......Code.
0000028F 00 0F 4C 69 6E 65 4E 75 6D 62 65 72 54 61 62 6C ..LineNumberTabl
0000029F 65 01 00 12 4C 6F 63 61 6C 56 61 72 69 61 62 6C e...LocalVariabl
000002AF 65 54 61 62 6C 65 01 00 0A 53 6F 75 72 63 65 46 eTable...SourceF
000002BF 69 6C 65 00 21 00 02 00 04 00 00 00 00 00 02 00 ile.!...........
000002CF 01 00 06 00 07 00 01 00 10 00 00 00 2F 00 01 00 ............/...
000002DF 01 00 00 00 05 2A B7 00 09 B1 00 00 00 02 00 11 .....*..........
000002EF 00 00 00 06 00 01 00 00 00 05 00 12 00 00 00 0C ................
000002FF 00 01 00 00 00 05 00 0A 00 0B 00 00 00 09 00 0C ................
0000030F 00 0D 00 01 00 10 00 00 00 1B 00 01 00 00 00 00 ................
0000031F 00 03 12 0F B0 00 00 00 01 00 11 00 00 00 06 00 ................
0000032F 01 00 00 00 08 00 01 00 13 00 00 00 02 00 05    ...............

-----------------------------------------------------------------------------
hello方法执行结果：Hello World~
```

程序执行后会在`TestASMHelloWorldDump`类同级的包下生成一个`TestASMHelloWorld`类，如下图：

![img](https://oss.javasec.org/images/image-20201021163840625.png)

## IDEA/Eclipse插件

初学ASM，读写ASM字节码对我们来说是非常困难的，但是我们可以借助开发工具的ASM插件，可以极大程度的帮助我们学习ASM。



### IDEA - ASM Bytecode Outline

在IDEA中插件中心搜索：`ASM Bytecode Outline`，就可以找到ASM字节码插件，如下图：

![img](https://oss.javasec.org/images/image-20201021193710065.png)

安装完`ASM Bytecode Outline`后选择任意Java类，右键菜单中会出现`Show Bytecode outline`选项，点击之后就可以看到该类对应的ASM和Bytecode代码，如下图：

![img](https://oss.javasec.org/images/image-20201021194226711.png)



### Eclipse - Bytecode Outline

Eclipse同IDEA，在插件中心搜索bytecode就可以找到`Bytecode Outline`插件，值得一提的是Eclipse的`Bytecode Outline`相比`IDEA`而言更加的方便，打开任意Java类会在`Bytecode`窗体中生成对应的ASM代码，点击任意行代码还能自动对应到高亮对应的ASM代码。

#### 安装Bytecode Outline

如果您使用的Eclipse版本相对较低（低版本的Eclipse自带了ASM依赖，如`Eclipse Photon Release (4.8.0)`）可直接在插件中心安装`Bytecode Outline`，否则需要先安装ASM依赖，点击`Help`->`Eclipse Marketplace...`，如下图：

![img](https://oss.javasec.org/images/image-20201021195157340.png)

然后搜索`bytecode`，找到`Bytecode Outline`，如下图：

![img](https://oss.javasec.org/images/image-20201021195157340.png)

点击`Instal`->`I accept the terms of the license agreement`->`Finish`：

![img](https://oss.javasec.org/images/image-20201021195253390.png)

提示安全警告，直接点击`Install anyway`：

![img](https://oss.javasec.org/images/image-20201021195347822.png)



安装完成后重启Eclipse即可。

#### 安装Eclipse ASM依赖库

如果您是使用的Eclipse版本较新可能会无法安装，提示：`Cannot complete the install because one or more required items could not be...`，这是因为新版本的Eclipse不自带ASM依赖库，需要我们先安装好ASM依赖然后才能安装`Bytecode Outline`插件。

点击`Help`->`Install New Software...`

![img](https://oss.javasec.org/images/image-20201021201200390.png)

然后在https://download.eclipse.org/tools/orbit/downloads/drops/选择对应的Eclipse版本：

![img](https://oss.javasec.org/images/image-20201021201957013.png)

复制仓库地址：

![img](https://oss.javasec.org/images/image-20201021202053530.png)

然后在`Work with`输入框中输入：`https://download.eclipse.org/tools/orbit/downloads/drops/I20200904215518/repository`，点击`Add..`，填入仓库名字，如下图：

![img](https://oss.javasec.org/images/image-20201021200357368.png)

选择`All Bundles`或者找到`ASM`相关依赖，并按照提示完成依赖安装，如下图：

![img](https://oss.javasec.org/images/image-20201021200428572.png)

### Bytecode Outline配置

安装好`Bytecode Outline`插件以后默认没有`Bytecode`窗体，需要再视图中添加`Bytecode`，点击`Window`->`Show View`->`Other`，如下图：

![img](https://oss.javasec.org/images/image-20201021203041991.png)

然后在弹出的视图窗体中输入`bytecode`后点击`open`，如下图：

![img](https://oss.javasec.org/images/image-20201021203116896.png)

随便写一个测试类，在`Bytecode`窗体中可以看到对应的`Bytecode`，如果需要看ASM代码，点击右侧菜单的`ASM图标`即可，如下图：

![img](https://oss.javasec.org/images/image-20201021203256732.png)

如果想对照查看Java和ASM代码，只需点击对应的Java代码就会自动高亮ASM部分的代码，如下图：

![img](https://oss.javasec.org/images/image-20201021203526682.png)

我们可以借助`Bytecode Outline`插件学习ASM，也可以直接使用`Bytecode Outline`生成的ASM代码来实现字节码编辑。