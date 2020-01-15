# Java 动态代理

`Java`反射提供了一种类动态代理机制，可以通过代理接口实现类来完成程序无侵入式扩展。

**Java动态代理主要使用场景：**

1. 统计方法执行所耗时间。
2. 在方法执行前后添加日志。
3. 检测方法的参数或返回值。
4. 方法访问权限控制。
5. 方法`Mock`测试。

## 动态代理API

创建动态代理类会使用到`java.lang.reflect.Proxy`类和`java.lang.reflect.InvocationHandler`接口。`java.lang.reflect.Proxy`主要用于生成动态代理类`Class`、创建代理类实例，该类实现了`java.io.Serializable`接口。

**`java.lang.reflect.Proxy`类主要方法如下：**

```java
package java.lang.reflect;

import java.lang.reflect.InvocationHandler;

/**
 * Creator: yz
 * Date: 2020/1/15
 */
public class Proxy implements java.io.Serializable {
  
  // 省去成员变量和部分类方法...

	/**
	 * 获取动态代理处理类对象
	 *
	 * @param proxy 返回调用处理程序的代理实例
	 * @return 代理实例的调用处理程序
	 * @throws IllegalArgumentException 如果参数不是一个代理实例
	 */
	public static InvocationHandler getInvocationHandler(Object proxy)
			throws IllegalArgumentException {
		...
	}

	/**
	 * 创建动态代理类实例
	 *
	 * @param loader     指定动态代理类的类加载器
	 * @param interfaces 指定动态代理类的类需要实现的接口数组
	 * @param h          动态代理处理类
	 * @return 返回动态代理生成的代理类实例
	 * @throws IllegalArgumentException 不正确的参数异常
	 */
	public static Object newProxyInstance(ClassLoader loader, Class<?>[] interfaces, InvocationHandler h)
			throws IllegalArgumentException {
		...
	}

	/**
	 * 创建动态代理类
	 *
	 * @param loader     定义代理类的类加载器
	 * @param interfaces 代理类要实现的接口列表
	 * @return 用指定的类加载器定义的代理类，它可以实现指定的接口
	 */
	public static Class<?> getProxyClass(ClassLoader loader, Class<?>... interfaces) {
		...
	}

	/**
	 * 检测某个类是否是动态代理类
	 *
	 * @param cl 要测试的类
	 * @return 如该类为代理类，则为 true，否则为 false
	 */
	public static boolean isProxyClass(Class<?> cl) {
		return java.lang.reflect.Proxy.class.isAssignableFrom(cl) && proxyClassCache.containsValue(cl);
	}

	/**
	 * 向指定的类加载器中定义一个类对象
	 *
	 * @param loader 类加载器
	 * @param name   类名
	 * @param b      类字节码
	 * @param off    截取开始位置
	 * @param len    截取长度
	 * @return JVM创建的类Class对象
	 */
	private static native Class defineClass0(ClassLoader loader, String name, byte[] b, int off, int len);

}
```

`java.lang.reflect.InvocationHandler`接口用于调用`Proxy`类生成的代理类方法，该类只有一个`invoke`方法。

**`java.lang.reflect.InvocationHandler`接口代码(注释直接搬的JDK6中文版文档)：**

```java
package java.lang.reflect;

import java.lang.reflect.Method;

/**
 * 每个代理实例都具有一个关联的调用处理程序。对代理实例调用方法时，将对方法调用进行编码并
 * 将其指派到它的调用处理程序的 invoke 方法。
 */
public interface InvocationHandler {

	/**
	 * 在代理实例上处理方法调用并返回结果。在与方法关联的代理实例上调用方法时，将在调用处理程序上调用此方法。
	 *
	 * @param proxy  在其上调用方法的代理实例
	 * @param method 对应于在代理实例上调用的接口方法的 Method 实例。Method 对象的声明类将是在其中声明
	 *               方法的接口，该接口可以是代理类赖以继承方法的代理接口的超接口。
	 * @param args   包含传入代理实例上方法调用的参数值的对象数组，如果接口方法不使用参数，
	 *               则为 null。基本类型的参数被包装在适当基本包装器类（如 java.lang.Integer
	 *               或 java.lang.Boolean）的实例中。
	 * @return 从代理实例的方法调用返回的值。如果接口方法的声明返回类型是基本类型，
	 * 则此方法返回的值一定是相应基本包装对象类的实例；否则，它一定是可分配到声明返回类型的类型。
	 * 如果此方法返回的值为 null 并且接口方法的返回类型是基本类型，则代理实例上的方法调用将抛出
	 * NullPointerException。否则，如果此方法返回的值与上述接口方法的声明返回类型不兼容，
	 * 则代理实例上的方法调用将抛出 ClassCastException。
	 * @throws Throwable 从代理实例上的方法调用抛出的异常。该异常的类型必须可以分配到在接口方法的
	 *                   throws 子句中声明的任一异常类型或未经检查的异常类型 java.lang.RuntimeException 或
	 *                   java.lang.Error。如果此方法抛出经过检查的异常，该异常不可分配到在接口方法的 throws 子句中
	 *                   声明的任一异常类型，代理实例的方法调用将抛出包含此方法曾抛出的异常的
	 */
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable;

}
```

## 使用java.lang.reflect.Proxy动态创建类对象

前面章节我们讲到了`ClassLoader`和`Unsafe`都有一个叫做`defineClassXXX`的`native`方法，我们可以通过调用这个`native`方法动态的向`JVM`创建一个类对象，而`java.lang.reflect.Proxy`类恰好也有这么一个`native`方法，所以我们也将可以通过调用`java.lang.reflect.Proxy`类`defineClass0`方法实现动态创建类对象。

**ProxyDefineClassTest示例代码：**

```java
package com.anbai.sec.proxy;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import static com.anbai.sec.classloader.TestClassLoader.TEST_CLASS_BYTES;
import static com.anbai.sec.classloader.TestClassLoader.TEST_CLASS_NAME;

/**
 * Creator: yz
 * Date: 2020/1/15
 */
public class ProxyDefineClassTest {

	public static void main(String[] args) {
		// 获取系统的类加载器，可以根据具体情况换成一个存在的类加载器
		ClassLoader classLoader = ClassLoader.getSystemClassLoader();

		try {
			// 反射java.lang.reflect.Proxy类获取其中的defineClass0方法
			Method method = Proxy.class.getDeclaredMethod("defineClass0", new Class[]{
					ClassLoader.class, String.class, byte[].class, int.class, int.class
			});

			// 修改方法的访问权限
			method.setAccessible(true);

			// 反射调用java.lang.reflect.Proxy.defineClass0()方法，动态向JVM注册
			// com.anbai.sec.classloader.TestHelloWorld类对象
			Class helloWorldClass = (Class) method.invoke(null, new Object[]{
					classLoader, TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length
			});

			// 输出TestHelloWorld类对象
			System.out.println(helloWorldClass);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
```

程序运行结果：

```java
class com.anbai.sec.classloader.TestHelloWorld
```

## 创建代理类实例

我们可以使用`Proxy.newProxyInstance`来创建动态代理类实例，或者使用`Proxy.getProxyClass()`获取代理类对象再反射的方式来创建，下面我们以`com.anbai.sec.proxy.FileSystem`接口为例，演示如何创建其动态代理类实例。

**`Proxy.newProxyInstance`示例代码：**

```java
// 创建UnixFileSystem类实例
FileSystem fileSystem = new UnixFileSystem();

// 使用JDK动态代理生成FileSystem动态代理类实例
FileSystem proxyInstance = (FileSystem) Proxy.newProxyInstance(
      FileSystem.class.getClassLoader(),// 指定动态代理类的类加载器
      new Class[]{FileSystem.class}, // 定义动态代理生成的类实现的接口
      new JDKInvocationHandler(fileSystem)// 动态代理处理类
);
```

**`Proxy.getProxyClass`反射示例代码：**

```java
// 创建UnixFileSystem类实例
FileSystem fileSystem = new UnixFileSystem();

// 创建动态代理处理类
InvocationHandler handler = new JDKInvocationHandler(fileSystem);

// 通过指定类加载器、类实现的接口数组生成一个动态代理类
Class proxyClass = Proxy.getProxyClass(
      FileSystem.class.getClassLoader(),// 指定动态代理类的类加载器
      new Class[]{FileSystem.class}// 定义动态代理生成的类实现的接口
);

// 使用反射获取Proxy类构造器并创建动态代理类实例
FileSystem proxyInstance = (FileSystem) proxyClass.getConstructor(
      new Class[]{InvocationHandler.class}).newInstance(new Object[]{handler}
);
```

## 动态代理添加方法调用日志示例

假设我们有一个叫做`FileSystem`接口，`UnixFileSystem`类实现了`FileSystem`接口，我们可以使用`JDK动态代理`的方式给`FileSystem`的接口方法执行前后都添加日志输出。

**com.anbai.sec.proxy.FileSystem示例代码：**

```java
package com.anbai.sec.proxy;

import java.io.File;
import java.io.Serializable;

/**
 * Creator: yz
 * Date: 2020/1/14
 */
public interface FileSystem extends Serializable {

	String[] list(File file);

}
```

**com.anbai.sec.proxy.UnixFileSystem示例代码：**

```java
package com.anbai.sec.proxy;

import java.io.File;

/**
 * Creator: yz
 * Date: 2020/1/14
 */
public class UnixFileSystem implements FileSystem {

	/* -- Disk usage -- */
	public int spaceTotal = 996;

	@Override
	public String[] list(File file) {
		System.out.println("正在执行[" + this.getClass().getName() + "]类的list方法，参数:[" + file + "]");

		return file.list();
	}

}
```

**com.anbai.sec.proxy.JDKInvocationHandler示例代码：**

```java
package com.anbai.sec.proxy;

import java.io.Serializable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

/**
 * Creator: yz
 * Date: 2020/1/14
 */
public class JDKInvocationHandler implements InvocationHandler, Serializable {

	private final Object target;

	public JDKInvocationHandler(Object target) {
		this.target = target;
	}

	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		// 为了不影响测试Demo的输出结果，这里忽略掉toString方法
		if ("toString".equals(method.getName())) {
			return method.invoke(target, args);
		}

		System.out.println("即将调用[" + target.getClass().getName() + "]类的[" + method.getName() + "]方法...");
		Object obj = method.invoke(target, args);
		System.out.println("已完成[" + target.getClass().getName() + "]类的[" + method.getName() + "]方法调用...");

		return obj;
	}

}
```

 **com.anbai.sec.proxy.FileSystemProxyTest示例代码：**

```java
package com.anbai.sec.proxy;

import java.io.File;
import java.lang.reflect.Proxy;
import java.util.Arrays;

/**
 * Creator: yz
 * Date: 2020/1/14
 */
public class FileSystemProxyTest {

	public static void main(String[] args) {
		// 创建UnixFileSystem类实例
		FileSystem fileSystem = new UnixFileSystem();

		// 使用JDK动态代理生成FileSystem动态代理类实例
		FileSystem proxyInstance = (FileSystem) Proxy.newProxyInstance(
				FileSystem.class.getClassLoader(),// 指定动态代理类的类加载器
				new Class[]{FileSystem.class}, // 定义动态代理生成的类实现的接口
				new JDKInvocationHandler(fileSystem)// 动态代理处理类
		);

		System.out.println("动态代理生成的类名:" + proxyInstance.getClass());
		System.out.println("----------------------------------------------------------------------------------------");
		System.out.println("动态代理生成的类名toString:" + proxyInstance.toString());
		System.out.println("----------------------------------------------------------------------------------------");

		// 使用动态代理的方式UnixFileSystem方法
		String[] files = proxyInstance.list(new File("."));

		System.out.println("----------------------------------------------------------------------------------------");
		System.out.println("UnixFileSystem.list方法执行结果:" + Arrays.toString(files));
		System.out.println("----------------------------------------------------------------------------------------");

		boolean isFileSystem     = proxyInstance instanceof FileSystem;
		boolean isUnixFileSystem = proxyInstance instanceof UnixFileSystem;

		System.out.println("动态代理类[" + proxyInstance.getClass() + "]是否是FileSystem类的实例:" + isFileSystem);
		System.out.println("----------------------------------------------------------------------------------------");
		System.out.println("动态代理类[" + proxyInstance.getClass() + "]是否是UnixFileSystem类的实例:" + isUnixFileSystem);
		System.out.println("----------------------------------------------------------------------------------------");
	}

}
```

程序执行结果：

```java
动态代理生成的类名:class com.sun.proxy.$Proxy0
----------------------------------------------------------------------------------------
动态代理生成的类名toString:com.anbai.sec.proxy.UnixFileSystem@194d6112
----------------------------------------------------------------------------------------
即将调用[com.anbai.sec.proxy.UnixFileSystem]类的[list]方法...
正在执行[com.anbai.sec.proxy.UnixFileSystem]类的list方法，参数:[.]
已完成[com.anbai.sec.proxy.UnixFileSystem]类的[list]方法调用...
----------------------------------------------------------------------------------------
UnixFileSystem.list方法执行结果:[javaweb-sec.iml, javaweb-sec-source, pom.xml, README.md, .gitignore, gitbook, .git, jni, .idea]
----------------------------------------------------------------------------------------
动态代理类[class com.sun.proxy.$Proxy0]是否是FileSystem类的实例:true
----------------------------------------------------------------------------------------
动态代理类[class com.sun.proxy.$Proxy0]是否是UnixFileSystem类的实例:false
----------------------------------------------------------------------------------------
```

## 动态代理类生成的$ProxyXXX类代码分析

`java.lang.reflect.Proxy`类是通过创建一个新的`Java类(类名为com.sun.proxy.$ProxyXXX)`的方式来实现无侵入的类方法代理功能的。

**动态代理生成出来的类有如下技术细节和特性：**

1. 动态代理的必须是接口类，通过`动态生成一个接口实现类`来代理接口的方法调用(`反射机制`)。
2. 动态代理类会由`java.lang.reflect.Proxy.ProxyClassFactory`创建。
3. `ProxyClassFactory`会调用`sun.misc.ProxyGenerator`类生成该类的字节码，并调用`java.lang.reflect.Proxy.defineClass0()`方法将该类注册到`JVM`。
4. 该类继承于`java.lang.reflect.Proxy`并实现了需要被代理的接口类，因为`java.lang.reflect.Proxy`类实现了`java.io.Serializable`接口，所以被代理的类支持`序列化/反序列化`。
5. 该类实现了代理接口类(示例中的接口类是`com.anbai.sec.proxy.FileSystem`)，会通过`ProxyGenerator`动态生成接口类(`FileSystem`)的所有方法，
6. 该类因为实现了代理的接口类，所以当前类是代理的接口类的实例(`proxyInstance instanceof FileSystem`为`true`)，但不是代理接口类的实现类的实例(`proxyInstance instanceof UnixFileSystem`为`false`)。
7. 该类方法中包含了被代理的接口类的所有方法，通过调用动态代理处理类(`InvocationHandler`)的`invoke`方法获取方法执行结果。
8. 该类代理的方式重写了`java.lang.Object`类的`toString`、`hashCode`、`equals`方法。
9. 如果动过动态代理生成了多个动态代理类，新生成的类名中的`0`会自增，如`com.sun.proxy.$Proxy0/$Proxy1/$Proxy2`。

**动态代理生成的`com.sun.proxy.$Proxy0`类代码：**

```java
package com.sun.proxy.$Proxy0;

import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.lang.reflect.UndeclaredThrowableException;

public final class $Proxy0 extends Proxy implements FileSystem {

	private static Method m1;

  // 实现的FileSystem接口方法，如果FileSystem里面有多个方法那么在这个类中将从m3开始n个成员变量
	private static Method m3;

	private static Method m0;

	private static Method m2;

	public $Proxy0(InvocationHandler var1) {
		super(var1);
	}

	public final boolean equals(Object var1) {
		try {
			return (Boolean) super.h.invoke(this, m1, new Object[]{var1});
		} catch (RuntimeException | Error var3) {
			throw var3;
		} catch (Throwable var4) {
			throw new UndeclaredThrowableException(var4);
		}
	}

	public final String[] list(File var1) {
		try {
			return (String[]) super.h.invoke(this, m3, new Object[]{var1});
		} catch (RuntimeException | Error var3) {
			throw var3;
		} catch (Throwable var4) {
			throw new UndeclaredThrowableException(var4);
		}
	}

	public final int hashCode() {
		try {
			return (Integer) super.h.invoke(this, m0, (Object[]) null);
		} catch (RuntimeException | Error var2) {
			throw var2;
		} catch (Throwable var3) {
			throw new UndeclaredThrowableException(var3);
		}
	}

	public final String toString() {
		try {
			return (String) super.h.invoke(this, m2, (Object[]) null);
		} catch (RuntimeException | Error var2) {
			throw var2;
		} catch (Throwable var3) {
			throw new UndeclaredThrowableException(var3);
		}
	}

	static {
		try {
			m1 = Class.forName("java.lang.Object").getMethod("equals", Class.forName("java.lang.Object"));
			m3 = Class.forName("com.anbai.sec.proxy.FileSystem").getMethod("list", Class.forName("java.io.File"));
			m0 = Class.forName("java.lang.Object").getMethod("hashCode");
			m2 = Class.forName("java.lang.Object").getMethod("toString");
		} catch (NoSuchMethodException var2) {
			throw new NoSuchMethodError(var2.getMessage());
		} catch (ClassNotFoundException var3) {
			throw new NoClassDefFoundError(var3.getMessage());
		}
	}
}
```

## 动态代理类实例序列化问题

动态代理类符合`Java`对象序列化条件，并且在`序列化/反序列化`时会被`ObjectInputStream/ObjectOutputStream`特殊处理。

**FileSystemProxySerializationTest示例代码：**

```java
package com.anbai.sec.proxy;

import java.io.*;
import java.lang.reflect.Proxy;

/**
 * Creator: yz
 * Date: 2020/1/14
 */
public class FileSystemProxySerializationTest {

   public static void main(String[] args) {
      try {
         // 创建UnixFileSystem类实例
         FileSystem fileSystem = new UnixFileSystem();

         // 使用JDK动态代理生成FileSystem动态代理类实例
         FileSystem proxyInstance = (FileSystem) Proxy.newProxyInstance(
               FileSystem.class.getClassLoader(),// 指定动态代理类的类加载器
               new Class[]{FileSystem.class}, // 定义动态代理生成的类实现的接口
               new JDKInvocationHandler(fileSystem)// 动态代理处理类
         );

         ByteArrayOutputStream baos = new ByteArrayOutputStream();

         // 创建Java对象序列化输出流对象
         ObjectOutputStream out = new ObjectOutputStream(baos);

         // 序列化动态代理类
         out.writeObject(proxyInstance);
         out.flush();
         out.close();

         // 利用动态代理类生成的二进制数组创建二进制输入流对象用于反序列化操作
         ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

         // 通过反序列化输入流(bais),创建Java对象输入流(ObjectInputStream)对象
         ObjectInputStream in = new ObjectInputStream(bais);

         // 反序列化输入流数据为FileSystem对象
         FileSystem test = (FileSystem) in.readObject();

         System.out.println("反序列化类实例类名:" + test.getClass());
         System.out.println("反序列化类实例toString:" + test.toString());
      } catch (IOException e) {
         e.printStackTrace();
      } catch (ClassNotFoundException e) {
         e.printStackTrace();
      }

   }

}
```

程序执行结果：

```java
反序列化类实例类名:class com.sun.proxy.$Proxy0
反序列化类实例toString:com.anbai.sec.proxy.UnixFileSystem@b07848
```

动态代理生成的类在`反序列化/反序列化`时不会序列化该类的成员变量，并且`serialVersionUID`为`0L` ，也将是说将该类的`Class`对象传递给`java.io.ObjectStreamClass`的静态`lookup`方法时，返回的`ObjectStreamClass`实例将具有以下特性：

1. 调用其`getSerialVersionUID`方法将返回`0L` 。
2. 调用其`getFields`方法将返回长度为零的数组。
3. 调用其`getField`方法将返回`null` 。

但其父类(`java.lang.reflect.Proxy`)在序列化时不受影响，父类中的`h`变量(`InvocationHandler`)将会被序列化，这个`h`存储了动态代理类的处理类实例以及动态代理的接口类的实现类的实例。

动态代理生成的对象(`com.sun.proxy.$ProxyXXX`)序列化的时候会使用一个特殊的协议：`TC_PROXYCLASSDESC(0x7D)`，这个常量在`java.io.ObjectStreamConstants`中定义的。在反序列化时也不会调用`java.io.ObjectInputStream`类的`resolveClass`方法而是调用`resolveProxyClass`方法来转换成类对象的。

详细描述请参考:[Dynamic Proxy Classes-Serialization](https://docs.oracle.com/javase/8/docs/technotes/guides/reflection/proxy.html#serial)