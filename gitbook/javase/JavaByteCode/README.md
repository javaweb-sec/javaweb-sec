# Java 字节码

Java源文件(`*.java`)通过编译后会变成`class文件`，`class文件`有固定的二进制格式，`class文件`的结构在JVM虚拟机规范[第四章：The class File Format](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html)中有详细的说明。本章节将学习`class文件结构`、`class文件解析`、`class文件反编译`以及`ASM字节码库`。

[Java语言和JVM虚拟机规范](https://docs.oracle.com/javase/specs/)：[《Java15语言规范》](https://docs.oracle.com/javase/specs/jls/se15/jls15.pdf)、[《Java15虚拟机实现规范》](https://docs.oracle.com/javase/specs/jvms/se15/jvms15.pdf)

**示例代码TestHelloWorld:**

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

**TestHelloWorld.java编译解析流程：**

![img](https://oss.javasec.org/images/image-20201015170935576.png)

**TestHelloWorld.java 源码、字节码：**

![img](https://oss.javasec.org/images/image-20201014104801579.png)

