# Java Agent

Java Agent和普通的Java类并没有任何区别，普通的Java程序中规定了`main`方法为程序入口，而Java Agent则将`premain`（Agent模式）和`agentmain`（Attach模式）作为了Agent程序的入口，如下：

```java
public static void premain(String args, Instrumentation inst) {}
public static void agentmain(String args, Instrumentation inst) {}
```

Java Agent还限制了我们必须以jar包的形式运行或加载，我们必须将编写好的Agent程序打包成一个jar文件。除此之外，Java Agent还强制要求了所有的jar文件中必须包含`/META-INFo/MANIFEST.MF`文件，且该文件中必须定义好`Premain-Class`（Agent模式）或`Agent-Class:`（Agent模式）配置，如：

```java
Premain-Class: com.anbai.sec.agent.JavaSecHelloWorldAgent
Agent-Class: com.anbai.sec.agent.JavaSecHelloWorldAgent
```

如果我们需要修改已经被JVM加载过的类的字节码，那么还需要设置在`MANIFEST.MF`中添加`Can-Retransform-Classes: true`或`Can-Redefine-Classes: true`。



## Agent模式

为了便于理解Agent机制，让我们来运行一个非常简单的`Java`的`HelloWorld`程序。

**HelloWorld示例代码：**

```java
package com.anbai.sec.agent;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Creator: yz
 * Date: 2020/10/29
 */
public class HelloWorld {

	private static void hello(String cmd) {
		// 获取当前系统时间
		String datetime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
		System.out.println("Time: " + datetime + "，执行命令：" + cmd);
	}

	public static void main(String[] args) {
		new Thread(new Runnable() {
			@Override
			public void run() {
				while (true) {
					try {
						// 调用hello方法
						hello("whoami");

						// sleep 1秒
						TimeUnit.SECONDS.sleep(1);
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
Time: 2020-10-29 20:35:20，执行命令：whoami
Time: 2020-10-29 20:35:21，执行命令：whoami
Time: 2020-10-29 20:35:22，执行命令：whoami
Time: 2020-10-29 20:35:23，执行命令：whoami
```

假设我们现在有一个需求：必须在不重新编译某个类的情况下(甚至有可能是不重启应用服务的情况下)动态的改变类方法的执行逻辑是非常困难的，但如果使用`Agent`的`Instrumentation API`就可以非常容易的实现了，例如在`HelloWorld`类的`hello`方法执行前输出该方法的参数值。

然后我们需要编写一个简单的测试类：

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
public class JavaSecHelloWorldAgent {

	/**
	 * 需要被Hook的类
	 */
	private static final String HOOK_CLASS = "com.anbai.sec.agent.HelloWorld";

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
			URL    agentURL  = JavaSecHelloWorldAgent.class.getProtectionDomain().getCodeSource().getLocation();
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

				// 只处理com.anbai.sec.agent.HelloWorld类的字节码
				if (className.equals(HOOK_CLASS)) {
					try {
						ClassPool classPool = ClassPool.getDefault();

						// 使用javassist将类二进制解析成CtClass对象
						CtClass ctClass = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));

						// 使用CtClass对象获取hello方法，类似于Java反射机制的clazz.getDeclaredMethod(xxx)
						CtMethod ctMethod = ctClass.getDeclaredMethod(
								"hello", new CtClass[]{classPool.getCtClass("java.lang.String")}
						);

						// 直接修改hello方法的字节码
						ctMethod.insertBefore("System.out.println(\"参数：\" + $1);");

						// 将使用javassist修改后的类字节码给JVM加载
						return ctClass.toBytecode();
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

添加pom.xml：

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

![image-20201029205623321](../../images/image-20201029205623321.png)

我们需要在运行`HelloWorld`的时候添加`-javaagent:jar路径`参数，例如：

```bash
cd ~/IdeaProjects/javaweb-sec/javaweb-sec-source/javasec-agent
java -javaagent:/Users/yz/IdeaProjects/javaweb-sec/javaweb-sec-source/javasec-agent/target/javasec-agent.jar -cp target/test-classes/ com.anbai.sec.agent.HelloWorld
```

程序执行结果：

```java
参数：whoami
Time: 2020-10-29 21:01:52，执行命令：whoami
参数：whoami
Time: 2020-10-29 21:01:53，执行命令：whoami
参数：whoami
Time: 2020-10-29 21:01:54，执行命令：whoami
```

由上示例可以看到`HelloWorld`类的`hello`方法已经被我们使用Java Agent机制动态编辑类字节码的方式修改成功了，`hello`方法执行前也动态的输出了：`参数：whoami`。

