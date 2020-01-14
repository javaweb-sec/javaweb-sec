# Java 动态代理

`Java`反射提供了一种类动态代理机制，可以通过代理接口实现类来完成程序无侵入式扩展。

**Java动态代理主要使用场景：**

1. 统计方法执行所耗时间。
2. 在方法执行前后添加日志。
3. 检测方法的参数或返回值。
4. 方法访问权限控制。
5. 方法`Mock`测试。

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
		// 获取UnixFileSystem类加载器
		ClassLoader classLoader = UnixFileSystem.class.getClassLoader();

		// 创建UnixFileSystem类实例
		FileSystem fileSystem = new UnixFileSystem();

		// 使用JDK动态代理生成FileSystem动态代理类实例
		FileSystem proxyInstance = (FileSystem) Proxy.newProxyInstance(
				classLoader,// 动态代理类的类加载器，动态代理生成的类将使用这个类加载器加载
				new Class[]{FileSystem.class}, // 定义动态代理生成的类实现的接口
				new JDKInvocationHandler(fileSystem)// 动态代理处理类
		);

		System.out.println("动态代理生成的类名:" + proxyInstance.getClass());
		System.out.println("----------------------------------------------------------------------------------------");
		System.out.println("动态代理生成的类实例:" + proxyInstance);
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
动态代理生成的类实例:com.anbai.sec.proxy.UnixFileSystem@1ae369b7
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

动态代理生成的`com.sun.proxy.$Proxy0`类代码：

```java
package com.anbai.sec.proxy;

import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.lang.reflect.UndeclaredThrowableException;

public final class $Proxy0 extends Proxy implements FileSystem {

	private static Method m1;

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

