# Java Agent

Java Agent和普通的Java类并没有任何区别，普通的Java程序中规定了`main`方法为程序入口，而Java Agent则将`premain`（Agent模式）和`agentmain`（Attach模式）作为了Agent程序的入口，两者所接受的参数是完全一致的，如下：

```java
public static void premain(String args, Instrumentation inst) {}
public static void agentmain(String args, Instrumentation inst) {}
```

Java Agent还限制了我们必须以jar包的形式运行或加载，我们必须将编写好的Agent程序打包成一个jar文件。除此之外，Java Agent还强制要求了所有的jar文件中必须包含`/META-INF/MANIFEST.MF`文件，且该文件中必须定义好`Premain-Class`（Agent模式）或`Agent-Class:`（Agent模式）配置，如：

```java
Premain-Class: com.anbai.sec.agent.CrackLicenseAgent
        Agent-Class: com.anbai.sec.agent.CrackLicenseAgent
```

如果我们需要修改已经被JVM加载过的类的字节码，那么还需要设置在`MANIFEST.MF`中添加`Can-Retransform-Classes: true`或`Can-Redefine-Classes: true`。



## Instrumentation

`java.lang.instrument.Instrumentation`是监测运行在`JVM`程序的`Java API`，利用`Instrumentation`我们可以实现如下功能：

1. 动态添加或移除自定义的`ClassFileTransformer`（`addTransformer/removeTransformer`），JVM会在类加载时调用Agent中注册的`ClassFileTransformer`；
2. 动态修改`classpath`（`appendToBootstrapClassLoaderSearch`、`appendToSystemClassLoaderSearch`），将Agent程序添加到`BootstrapClassLoader`和`SystemClassLoaderSearch`（对应的是`ClassLoader类的getSystemClassLoader方法`，默认是`sun.misc.Launcher$AppClassLoader`）中搜索；
3. 动态获取所有`JVM`已加载的类(`getAllLoadedClasses`)；
4. 动态获取某个类加载器已实例化的所有类(`getInitiatedClasses`)。
5. 重定义某个已加载的类的字节码(`redefineClasses`)。
6. 动态设置`JNI`前缀(`setNativeMethodPrefix`)，可以实现Hook native方法。
7. 重新加载某个已经被JVM加载过的类字节码`retransformClasses`)。

**`Instrumentation`类方法如下：**

![img](https://oss.javasec.org/images/07EC4F97-CD49-41E6-95CE-FEB000325E33.png)



## ClassFileTransformer

`java.lang.instrument.ClassFileTransformer`是一个转换类文件的代理接口，我们可以在获取到`Instrumentation`对象后通过`addTransformer`方法添加自定义类文件转换器。

示例中我们使用了`addTransformer`注册了一个我们自定义的`Transformer`到`Java Agent`，当有新的类被`JVM`加载时`JVM`会自动回调用我们自定义的`Transformer`类的`transform`方法，传入该类的`transform`信息(`类名、类加载器、类字节码`等)，我们可以根据传入的类信息决定是否需要修改类字节码，修改完字节码后我们将新的类字节码返回给`JVM`，`JVM`会验证类和相应的修改是否合法，如果符合类加载要求`JVM`会加载我们修改后的类字节码。

**`ClassFileTransformer类代码：`**

```java
package java.lang.instrument;

public interface ClassFileTransformer {
  
  /**
     * 类文件转换方法，重写transform方法可获取到待加载的类相关信息
     *
     * @param loader              定义要转换的类加载器；如果是引导加载器，则为 null
     * @param className           类名,如:java/lang/Runtime
     * @param classBeingRedefined 如果是被重定义或重转换触发，则为重定义或重转换的类；如果是类加载，则为 null
     * @param protectionDomain    要定义或重定义的类的保护域
     * @param classfileBuffer     类文件格式的输入字节缓冲区（不得修改）
     * @return 字节码byte数组。
     */
    byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer);
  
}
```

**重写`transform`方法需要注意以下事项：**

1. `ClassLoader`如果是被`Bootstrap ClassLoader(引导类加载器)`所加载那么`loader`参数的值是空。
2. 修改类字节码时需要特别注意插入的代码在对应的`ClassLoader`中可以正确的获取到，否则会报`ClassNotFoundException`，比如修改`java.io.FileInputStream(该类由Bootstrap ClassLoader加载)`时插入了我们检测代码，那么我们将必须保证`FileInputStream`能够获取到我们的检测代码类。
3. `JVM`类名的书写方式路径方式：`java/lang/String`而不是我们常用的类名方式：`java.lang.String`。
4. 类字节必须符合`JVM`校验要求，如果无法验证类字节码会导致`JVM`崩溃或者`VerifyError(类验证错误)`。
5. 如果修改的是`retransform`类(修改已被`JVM`加载的类)，修改后的类字节码不得`新增方法`、`修改方法参数`、`类成员变量`。
6. `addTransformer`时如果没有传入`retransform`参数(默认是`false`)就算`MANIFEST.MF`中配置了`Can-Redefine-Classes: true`而且手动调用了`retransformClasses`方法也一样无法`retransform`。
7. 卸载`transform`时需要使用创建时的`Instrumentation`实例。



## Agent 实现破解License示例

学习Java Agent除了可以做`APM`、`RASP`等产品，我们还可以做一些趣味性事情，比如我们可以使用Agent机制实现Java商业软件破解，我们常用的`IntelliJ IDEA`就是使用Agent方式动态修改License类校验逻辑来实现破解的。

假设我们有一个Java类`CrackLicenseTest`，每五秒钟就会自动调用`checkExpiry`方法检测授权是否过期，如果过期就会一直不断的提示重新购买授权（或者直接退出Java程序）。

**检测授权时间是否过期示例代码：**

```java
package com.anbai.sec.agent;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Creator: yz
 * Date: 2020/10/29
 */
public class CrackLicenseTest {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private static boolean checkExpiry(String expireDate) {
        try {
            Date date = DATE_FORMAT.parse(expireDate);

            // 检测当前系统时间早于License授权截至时间
            if (new Date().before(date)) {
                return false;
            }
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return true;
    }

    public static void main(String[] args) {
        // 设置一个已经过期的License时间
        final String expireDate = "2020-10-01 00:00:00";

        new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        String time = "[" + DATE_FORMAT.format(new Date()) + "] ";

                        // 检测license是否已经过期
                        if (checkExpiry(expireDate)) {
                            System.err.println(time + "您的授权已过期，请重新购买授权！");
                        } else {
                            System.out.println(time + "您的授权正常，截止时间为：" + expireDate);
                        }

                        // sleep 1秒
                        TimeUnit.SECONDS.sleep(5);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }).start();
    }

}
```

程序运行结果：

```bash
[2020-10-29 23:51:44] 您的授权已过期，请重新购买授权！
[2020-10-29 23:51:49] 您的授权已过期，请重新购买授权！
[2020-10-29 23:51:54] 您的授权已过期，请重新购买授权！
[2020-10-29 23:51:59] 您的授权已过期，请重新购买授权！
[2020-10-29 23:52:04] 您的授权已过期，请重新购买授权！
```

如果我们要破解这种简单的基于系统时间检测授权是否过期的程序我们有非常多的实现方式，例如：修改系统时间、破解License算法，修改程序授权到期时间、修改检测是否到期类方法的业务逻辑等。

修改类方法业务逻辑又有多种方法，如：反编译类文件，修改类方法、使用字节码编辑工具，修改类方法字节码、使用Java Agent + 字节码编辑工具，在程序校验时修改类字节码。

在不重新编译某个类的情况下(甚至有可能是不重启Java应用服务的情况下)动态的改变类方法的执行逻辑是非常困难的，但如果使用`Agent`的`Instrumentation API`就可以非常容易的实现了。

破解示例中的`CrackLicenseTest`的授权检测方法只需要修改`checkExpiry`的返回值为`false`就行了或者修改`expireDate`参数值为一个100年以后的时间。

**破解CrackLicenseTest的授权检测示例代码：**

```java
/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.agent;

import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.net.URL;
import java.security.ProtectionDomain;
import java.util.List;

/**
 * Creator: yz
 * Date: 2020/1/2
 */
public class CrackLicenseAgent {

    /**
     * 需要被Hook的类
     */
    private static final String HOOK_CLASS = "com.anbai.sec.agent.CrackLicenseTest";

    /**
     * Java Agent模式入口
     *
     * @param args 命令参数
     * @param inst Instrumentation
     */
    public static void premain(String args, final Instrumentation inst) {
        loadAgent(args, inst);
    }

    /**
     * Java Attach模式入口
     *
     * @param args 命令参数
     * @param inst Instrumentation
     */
    public static void agentmain(String args, final Instrumentation inst) {
        loadAgent(args, inst);
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            List<VirtualMachineDescriptor> list = VirtualMachine.list();

            for (VirtualMachineDescriptor desc : list) {
                System.out.println("进程ID：" + desc.id() + "，进程名称：" + desc.displayName());
            }

            return;
        }

        // Java进程ID
        String pid = args[0];

        try {
            // 注入到JVM虚拟机进程
            VirtualMachine vm = VirtualMachine.attach(pid);

            // 获取当前Agent的jar包路径
            URL agentURL = CrackLicenseAgent.class.getProtectionDomain().getCodeSource().getLocation();
            String agentPath = new File(agentURL.toURI()).getAbsolutePath();

            // 注入Agent到目标JVM
            vm.loadAgent(agentPath);
            vm.detach();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 加载Agent
     *
     * @param arg  命令参数
     * @param inst Instrumentation
     */
    private static void loadAgent(String arg, final Instrumentation inst) {
        // 创建ClassFileTransformer对象
        ClassFileTransformer classFileTransformer = createClassFileTransformer();

        // 添加自定义的Transformer，第二个参数true表示是否允许Agent Retransform，
        // 需配合MANIFEST.MF中的Can-Retransform-Classes: true配置
        inst.addTransformer(classFileTransformer, true);

        // 获取所有已经被JVM加载的类对象
        Class[] loadedClass = inst.getAllLoadedClasses();

        for (Class clazz : loadedClass) {
            String className = clazz.getName();

            if (inst.isModifiableClass(clazz)) {
                // 使用Agent重新加载HelloWorld类的字节码
                if (className.equals(HOOK_CLASS)) {
                    try {
                        inst.retransformClasses(clazz);
                    } catch (UnmodifiableClassException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    private static ClassFileTransformer createClassFileTransformer() {
        return new ClassFileTransformer() {

            /**
             * 类文件转换方法，重写transform方法可获取到待加载的类相关信息
             *
             * @param loader              定义要转换的类加载器；如果是引导加载器，则为 null
             * @param className           类名,如:java/lang/Runtime
             * @param classBeingRedefined 如果是被重定义或重转换触发，则为重定义或重转换的类；如果是类加载，则为 null
             * @param protectionDomain    要定义或重定义的类的保护域
             * @param classfileBuffer     类文件格式的输入字节缓冲区（不得修改）
             * @return 字节码byte数组。
             */
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) {

                // 将目录路径替换成Java类名
                className = className.replace("/", ".");

                // 只处理com.anbai.sec.agent.CrackLicenseTest类的字节码
                if (className.equals(HOOK_CLASS)) {
                    try {
                        ClassPool classPool = ClassPool.getDefault();

                        // 使用javassist将类二进制解析成CtClass对象
                        CtClass ctClass = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));

                        // 使用CtClass对象获取checkExpiry方法，类似于Java反射机制的clazz.getDeclaredMethod(xxx)
                        CtMethod ctMethod = ctClass.getDeclaredMethod(
                                "checkExpiry", new CtClass[]{classPool.getCtClass("java.lang.String")}
                        );

                        // 在checkExpiry方法执行前插入输出License到期时间代码
                        ctMethod.insertBefore("System.out.println(\"License到期时间：\" + $1);");

                        // 修改checkExpiry方法的返回值，将授权过期改为未过期
                        ctMethod.insertAfter("return false;");

                        // 修改后的类字节码
                        classfileBuffer = ctClass.toBytecode();
                        File classFilePath = new File(new File(System.getProperty("user.dir"), "javaweb-sec-source/javasec-agent/src/main/java/com/anbai/sec/agent/"), "CrackLicenseTest.class");

                        // 写入修改后的字节码到class文件
                        FileOutputStream fos = new FileOutputStream(classFilePath);
                        fos.write(classfileBuffer);
                        fos.flush();
                        fos.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                return classfileBuffer;
            }
        };
    }

}
```

然后再添加pom.xml：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

    <parent>
        <artifactId>javaweb-sec-source</artifactId>
        <groupId>com.anbai</groupId>
        <version>1.0.0</version>
    </parent>

    <modelVersion>4.0.0</modelVersion>
    <artifactId>javasec-agent</artifactId>
    <packaging>jar</packaging>

    <properties>
        <asm.version>9.0</asm.version>
        <java.version>1.7</java.version>
        <package.name>com.anbai.sec.agent</package.name>
        <manifest-file.name>MANIFEST.MF</manifest-file.name>
        <maven-jar-plugin.version>2.3.2</maven-jar-plugin.version>
        <maven-shade-plugin.version>3.2.2</maven-shade-plugin.version>
    </properties>

    <dependencies>

        <dependency>
            <groupId>org.javassist</groupId>
            <artifactId>javassist</artifactId>
            <version>${javassist.version}</version>
        </dependency>

        <dependency>
            <groupId>org.javaweb</groupId>
            <artifactId>javaweb-utils</artifactId>
            <version>${javaweb.version}</version>
        </dependency>

        <dependency>
            <groupId>com.sun</groupId>
            <artifactId>tools</artifactId>
            <version>${java.version}</version>
            <scope>system</scope>
            <systemPath>${java.home}/../lib/tools.jar</systemPath>
        </dependency>

    </dependencies>

    <build>
        <finalName>javasec-agent</finalName>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <configuration>
                    <source>${java.version}</source>
                    <target>${java.version}</target>
                    <encoding>UTF-8</encoding>
                </configuration>
            </plugin>

            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-jar-plugin</artifactId>
                <version>${maven-jar-plugin.version}</version>

                <configuration>
                    <archive>
                        <manifestFile>src/main/resources/${manifest-file.name}</manifestFile>
                    </archive>
                </configuration>
            </plugin>

            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-shade-plugin</artifactId>
                <version>${maven-shade-plugin.version}</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals>
                            <goal>shade</goal>
                        </goals>
                        <configuration>
                            <filters>
                                <filter>
                                    <artifact>*:*</artifact>
                                    <excludes>
                                        <exclude>MANIFEST.MF</exclude>
                                        <exclude>META-INF/maven/</exclude>
                                    </excludes>
                                </filter>
                            </filters>

                            <artifactSet>
                                <includes>
                                    <include>org.javassist:javassist:jar:*</include>
                                    <include>org.javaweb:javaweb-utils:jar:*</include>
                                </includes>
                            </artifactSet>

                            <!-- 修改第三方依赖包名称 -->
                            <relocations>
                                <relocation>
                                    <pattern>com.anbai.sec.agent</pattern>
                                    <shadedPattern>${package.name}</shadedPattern>
                                </relocation>
                                <relocation>
                                    <pattern>org.apache</pattern>
                                    <shadedPattern>${package.name}.deps.org.apache</shadedPattern>
                                </relocation>
                                <relocation>
                                    <pattern>org.javaweb</pattern>
                                    <shadedPattern>${package.name}.deps.org.javaweb</shadedPattern>
                                </relocation>
                                <relocation>
                                    <pattern>javassist</pattern>
                                    <shadedPattern>${package.name}.deps.javassist</shadedPattern>
                                </relocation>
                            </relocations>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>

</project>
```

最后再执行如下命令使用`Maven`构建`Agent Jar`包：

```bash
cd ~/IdeaProjects/javaweb-sec/javaweb-sec-source/javasec-agent
mvn clean install
```

`Maven`构建完成后在`javaweb-sec/javaweb-sec-source/javasec-agent/target`目录会自动生成一个`javasec-agent.jar`文件。

![img](https://oss.javasec.org/images/image-20201029205623321.png)



## Agent模式

如果以Agent模式运行破解程序，需要我们在启动`CrackLicenseTest`的时候添加JVM参数：`-javaagent:jar路径`，例如：

```bash
cd ~/IdeaProjects/javaweb-sec/javaweb-sec-source/javasec-agent
java -javaagent:target/javasec-agent.jar -classpath target/test-classes/ com.anbai.sec.agent.CrackLicenseTest
```

程序执行结果：

![img](https://oss.javasec.org/images/image-20201101010058593.png)

生成的`CrackLicenseTest.class`如下：

![img](https://oss.javasec.org/images/image-20201103103324443.png)

由上示例可以看到`CrackLicenseTest`类的`checkExpiry`方法字节码已经被我们修改成功了 。

## Attach模式

如果我们希望在`CrackLicenseTest`运行时不重启该Java程序的情况下运行我们的破解程序就需要以Attach模式运行了。Attach模式需要知道我们运行的Java程序进程ID，通过Java虚拟机的进程注入方式实现可以将我们的Agent程序动态的注入到一个已在运行中的Java程序中。

我们可以使用JDK自带的`jps`命令获取本机运行的所有的Java进程，如：

```java
[robert@192:~]$ jps -l
14608 org.jetbrains.jps.cmdline.Launcher
14931 org.jd.gui.OsxApp
1075 
6809 org.jetbrains.idea.maven.server.RemoteMavenServer36
15820 com.anbai.sec.agent.CrackLicenseTest
15823 sun.tools.jps.Jps
```

通过进程的名字`com.anbai.sec.agent.CrackLicenseTest`就可以找到我们需要注入的进程ID为`15823`。如果我们想要直接借助Java程序来获取所有的JVM进程也是可以的，使用`com.sun.tools.attach.VirtualMachine`的`list`方法即可获取本机所有运行的Java进程，如：

```java
List<VirtualMachineDescriptor> list = VirtualMachine.list();

for (VirtualMachineDescriptor desc : list) {
    System.out.println("进程ID：" + desc.id() + "，进程名称：" + desc.displayName());
}
```

有了进程ID我们就可以使用Attach API注入Agent了，Attach Java进程注入示例代码如下：

```java
// Java进程ID
String pid = args[0];

// 设置Agent文件的绝对路径
String agentPath = "/xxx/agent.jar";

// 注入到JVM虚拟机进程
VirtualMachine vm = VirtualMachine.attach(pid);

// 注入Agent到目标JVM
vm.loadAgent(agentPath);
vm.detach();
```

使用Attach模式启动Agent程序时需要使用到JDK目录下的`lib/tools.jar`，如果没有配置`CLASS_PATH`环境变量的话需要在运行Agent程序时添加`-classpath $JAVA_HOME/lib/tools.jar`参数，否则我们无法使用Attach API，如下：

```bash
cd ~/IdeaProjects/javaweb-sec/javaweb-sec-source/javasec-agent
java -classpath $JAVA_HOME/lib/tools.jar:target/javasec-agent.jar com.anbai.sec.agent.CrackLicenseAgent
```

程序执行结果如下：

![image-20201101013153908](https://oss.javasec.org/images/image-20201101013153908.png)

当Attach成功后我们可以看到原来的进程输出结果也已经不在输出授权过期提示信息了，如下图：

![img](https://oss.javasec.org/images/image-20201101013416799.png)

使用Attach模式需要特别的需要注意和Agent模式的区别，因为Attach是运行在Java程序启动后，所以我们需要修改的Java类很有可能已经被JVM加载了，而已加载的Java类是不会再被Agent处理的，这时候我们需要在Attach到目标进程后`retransformClasses`，让JVM重新该Java类，这样我们就可以使用Agent机制修改该类的字节码了。

