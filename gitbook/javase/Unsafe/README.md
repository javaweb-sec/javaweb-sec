# sun.misc.Unsafe

`sun.misc.Unsafe`是Java底层API(`仅限Java内部使用,反射可调用`)提供的一个神奇的Java类，`Unsafe`提供了非常底层的`内存、CAS、线程调度、类、对象`等操作、`Unsafe`正如它的名字一样它提供的几乎所有的方法都是不安全的，本节只讲解如何使用`Unsafe`定义Java类、创建类实例。

## 如何获取Unsafe对象

`Unsafe`是Java内部API，外部是禁止调用的，在编译Java类时如果检测到引用了`Unsafe`类也会有禁止使用的警告：`Unsafe是内部专用 API, 可能会在未来发行版中删除`。

**`sun.misc.Unsafe`代码片段：**

```java
import sun.reflect.CallerSensitive;
import sun.reflect.Reflection;

public final class Unsafe {

	private static final Unsafe theUnsafe;

	static {
		theUnsafe = new Unsafe();
		省去其他代码......
	}

	private Unsafe() {
	}

	@CallerSensitive
	public static Unsafe getUnsafe() {
		Class var0 = Reflection.getCallerClass();
		if (var0.getClassLoader() != null) {
			throw new SecurityException("Unsafe");
		} else {
			return theUnsafe;
		}
	}

	省去其他代码......
}
```

由上代码片段可以看到，`Unsafe`类是一个不能被继承的类且不能直接通过`new`的方式创建`Unsafe`类实例，如果通过`getUnsafe`方法获取`Unsafe`实例还会检查类加载器，默认只允许`Bootstrap Classloader`调用。

既然无法直接通过`Unsafe.getUnsafe()`的方式调用，那么可以使用反射的方式去获取`Unsafe`类实例。

**反射获取`Unsafe`类实例代码片段：**

```java
// 反射获取Unsafe的theUnsafe成员变量
Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");

// 反射设置theUnsafe访问权限
theUnsafeField.setAccessible(true);

// 反射获取theUnsafe成员变量值
Unsafe unsafe = (Unsafe) theUnsafeField.get(null);
```

当然我们也可以用反射创建`Unsafe`类实例的方式去获取`Unsafe`对象：

```java
// 获取Unsafe无参构造方法
Constructor constructor = Unsafe.class.getDeclaredConstructor();

// 修改构造方法访问权限
constructor.setAccessible(true);

// 反射创建Unsafe类实例，等价于 Unsafe unsafe1 = new Unsafe();
Unsafe unsafe1 = (Unsafe) constructor.newInstance();
```

获取到了`Unsafe`对象我们就可以调用内部的方法了。

## allocateInstance无视构造方法创建类实例

假设我们有一个叫`com.anbai.sec.unsafe.UnSafeTest`的类，因为某种原因我们不能直接通过反射的方式去创建`UnSafeTest`类实例，那么这个时候使用`Unsafe`的`allocateInstance`方法就可以绕过这个限制了。

**UnSafeTest代码片段：**

```java
public class UnSafeTest {

   private UnSafeTest() {
      // 假设RASP在这个构造方法中插入了Hook代码，我们可以利用Unsafe来创建类实例
      System.out.println("init...");
   }

}  
```

**使用Unsafe创建UnSafeTest对象：**

```java
// 使用Unsafe创建UnSafeTest类实例
UnSafeTest test = (UnSafeTest) unsafe1.allocateInstance(UnSafeTest.class);
```

Google的`GSON`库在JSON反序列化的时候就使用这个方式来创建类实例，在渗透测试中也会经常遇到这样的限制，比如RASP限制了`java.io.FileInputStream`类的构造方法导致我们无法读文件或者限制了`UNIXProcess/ProcessImpl`类的构造方法导致我们无法执行本地命令等。

## defineClass直接调用JVM创建类对象

`ClassLoader`章节我们讲了通过`ClassLoader`类的`defineClass0/1/2`方法我们可以直接向JVM中注册一个类，如果`ClassLoader`被限制的情况下我们还可以使用`Unsafe`的`defineClass`方法来实现同样的功能。

`Unsafe`提供了一个通过传入类名、类字节码的方式就可以定义类的`defineClass`方法：

`public native Class defineClass(String var1, byte[] var2, int var3, int var4);`

`public native Class<?> defineClass(String var1, byte[] var2, int var3, int var4, ClassLoader var5, ProtectionDomain var6);`

**使用Unsafe创建TestHelloWorld对象：**

```java
// 使用Unsafe向JVM中注册com.anbai.sec.classloader.TestHelloWorld类
Class helloWorldClass = unsafe1.defineClass(TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length);
```

或调用需要传入类加载器和保护域的方法：

```java
// 获取系统的类加载器
ClassLoader classLoader = ClassLoader.getSystemClassLoader();

// 创建默认的保护域
ProtectionDomain domain = new ProtectionDomain(
	new CodeSource(null, (Certificate[]) null), null, classLoader, null
);

// 使用Unsafe向JVM中注册com.anbai.sec.classloader.TestHelloWorld类
Class helloWorldClass = unsafe1.defineClass(
	TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length, classLoader, domain
);
```

`Unsafe`还可以通过`defineAnonymousClass`方法创建内部类，这里不再多做测试。

**注意：**

这个实例仅适用于`Java 8`以前的版本如果在`Java 8`中应该使用应该调用需要传类加载器和保护域的那个方法。`Java 11`开始`Unsafe`类已经把`defineClass`方法移除了(`defineAnonymousClass`方法还在)，虽然可以使用`java.lang.invoke.MethodHandles.Lookup.defineClass`来代替，但是`MethodHandles`只是间接的调用了`ClassLoader`的`defineClass`，所以一切也就回到了`ClassLoader`。