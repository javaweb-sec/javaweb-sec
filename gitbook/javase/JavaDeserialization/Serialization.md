# Java 序列化/反序列化

在Java中实现对象反序列化非常简单，实现`java.io.Serializable(内部序列化)`或`java.io.Externalizable(外部序列化)`接口即可被序列化(`Externalizable`接口只是实现了`java.io.Serializable`接口)。

反序列化类对象时有如下限制：

1. 被反序列化的类必须存在。
2. `serialVersionUID`值必须一致。

除此之外，**反序列化类对象是不会调用该类构造方法**的，因为在反序列化创建类实例时使用了`sun.reflect.ReflectionFactory.newConstructorForSerialization`创建了一个反序列化专用的`Constructor(反射构造方法对象)`，使用这个特殊的`Constructor`可以绕过构造方法创建类实例(前面章节讲` sun.misc.Unsafe` 的时候我们提到了使用`allocateInstance`方法也可以实现绕过构造方法创建类实例)。

**使用反序列化方式创建类实例代码片段：**

```java
package com.anbai.sec.serializes;

import sun.reflect.ReflectionFactory;

import java.lang.reflect.Constructor;

/**
 * 使用反序列化方式在不调用类构造方法的情况下创建类实例
 * Creator: yz
 * Date: 2019/12/20
 */
public class ReflectionFactoryTest {

	public static void main(String[] args) {
		try {
			// 获取sun.reflect.ReflectionFactory对象
			ReflectionFactory factory = ReflectionFactory.getReflectionFactory();

			// 使用反序列化方式获取DeserializationTest类的构造方法
			Constructor constructor = factory.newConstructorForSerialization(
					DeserializationTest.class, Object.class.getConstructor()
			);

			// 实例化DeserializationTest对象
			System.out.println(constructor.newInstance());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
```

程序运行结果：

```java
com.anbai.sec.serializes.DeserializationTest@2b650cea
```

具体细节可参考 [不用构造方法也能创建对象](https://www.iteye.com/topic/850027)。

## ObjectInputStream、ObjectOutputStream

`java.io.ObjectOutputStream`类最核心的方法是`writeObject`方法，即序列化类对象。

`java.io.ObjectInputStream`类最核心的功能是`readObject`方法，即反序列化类对象。

所以，只需借助`ObjectInputStream`和`ObjectOutputStream`类我们就可以实现类的序列化和反序列化功能了。

### java.io.Serializable

`java.io.Serializable`是一个空的接口,我们不需要实现`java.io.Serializable`的任何方法，代码如下:

```java
public interface Serializable {
}
```

您可能会好奇我们实现一个空接口有什么意义？其实实现`java.io.Serializable`接口仅仅只用于`标识这个类可序列化`。实现了`java.io.Serializable`接口的类原则上都需要生产一个`serialVersionUID`常量，反序列化时如果双方的`serialVersionUID`不一致会导致`InvalidClassException` 异常。如果可序列化类未显式声明 `serialVersionUID`，则序列化运行时将基于该类的各个方面计算该类的默认 `serialVersionUID`值。

**`DeserializationTest.java`测试代码如下：**

```java
package com.anbai.sec.serializes;

import java.io.*;
import java.util.Arrays;

/**
 * Creator: yz
 * Date: 2019/12/15
 */
public class DeserializationTest implements Serializable {

	private String username;

	private String email;

	// 省去get/set方法....

	public static void main(String[] args) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try {
			// 创建DeserializationTest类，并类设置属性值
			DeserializationTest t = new DeserializationTest();
			t.setUsername("yz");
			t.setEmail("admin@javaweb.org");

			// 创建Java对象序列化输出流对象
			ObjectOutputStream out = new ObjectOutputStream(baos);

			// 序列化DeserializationTest类
			out.writeObject(t);
			out.flush();
			out.close();

			// 打印DeserializationTest类序列化以后的字节数组，我们可以将其存储到文件中或者通过Socket发送到远程服务地址
			System.out.println("DeserializationTest类序列化后的字节数组:" + Arrays.toString(baos.toByteArray()));

			// 利用DeserializationTest类生成的二进制数组创建二进制输入流对象用于反序列化操作
			ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

			// 通过反序列化输入流(bais),创建Java对象输入流(ObjectInputStream)对象
			ObjectInputStream in = new ObjectInputStream(bais);

			// 反序列化输入流数据为DeserializationTest对象
			DeserializationTest test = (DeserializationTest) in.readObject();
			System.out.println("用户名:" + test.getUsername() + ",邮箱:" + test.getEmail());

			// 关闭ObjectInputStream输入流
			in.close();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

}
```

程序执行结果如下：

```
DeserializationTest类序列化后的字节数组:[-84, -19, 0, 5, 115, 114, 0, 44, 99, 111, 109, 46, 97, 110, 98, 97, 105, 46, 115, 101, 99, 46, 115, 101, 114, 105, 97, 108, 105, 122, 101, 115, 46, 68, 101, 115, 101, 114, 105, 97, 108, 105, 122, 97, 116, 105, 111, 110, 84, 101, 115, 116, 74, 36, 49, 16, -110, 39, 13, 76, 2, 0, 2, 76, 0, 5, 101, 109, 97, 105, 108, 116, 0, 18, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 76, 0, 8, 117, 115, 101, 114, 110, 97, 109, 101, 113, 0, 126, 0, 1, 120, 112, 116, 0, 17, 97, 100, 109, 105, 110, 64, 106, 97, 118, 97, 119, 101, 98, 46, 111, 114, 103, 116, 0, 2, 121, 122]
用户名:yz,邮箱:admin@javaweb.org
```

核心逻辑其实就是使用`ObjectOutputStream`类的`writeObject`方法序列化`DeserializationTest`类，使用`ObjectInputStream`类的`readObject`方法反序列化`DeserializationTest`类而已。

简化后的代码片段如下：

```java
// 序列化DeserializationTest类
ObjectOutputStream out = new ObjectOutputStream(baos);
out.writeObject(t);

// 反序列化输入流数据为DeserializationTest对象
ObjectInputStream in = new ObjectInputStream(bais);
DeserializationTest test = (DeserializationTest) in.readObject();
```

`ObjectOutputStream`序列化类对象的主要流程是首先判断序列化的类是否重写了`writeObject`方法，如果重写了就调用序列化对象自身的`writeObject`方法序列化，序列化时会先写入类名信息，其次是写入成员变量信息(通过反射获取所有不包含被`transient`修饰的变量和值)。

### java.io.Externalizable

`java.io.Externalizable`和`java.io.Serializable`几乎一样，只是`java.io.Externalizable`接口定义了`writeExternal`和`readExternal`方法需要序列化和反序列化的类实现，其余的和`java.io.Serializable`并无差别。

**java.io.Externalizable.java:**

```java
public interface Externalizable extends java.io.Serializable {
  
  void writeExternal(ObjectOutput out) throws IOException;
  
  void readExternal(ObjectInput in) throws IOException, ClassNotFoundException;
  
}
```

**`ExternalizableTest.java`测试代码如下：**

```java
package com.anbai.sec.serializes;

import java.io.*;
import java.util.Arrays;

/**
 * Creator: yz
 * Date: 2019/12/15
 */
public class ExternalizableTest implements java.io.Externalizable {

	private String username;

	private String email;

	// 省去get/set方法....

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeObject(username);
		out.writeObject(email);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		this.username = (String) in.readObject();
		this.email = (String) in.readObject();
	}

	public static void main(String[] args) {
    	// 省去测试代码，因为和DeserializationTest一样...
	}

}
```

程序执行结果如下：

```java
ExternalizableTest类序列化后的字节数组:[-84, -19, 0, 5, 115, 114, 0, 43, 99, 111, 109, 46, 97, 110, 98, 97, 105, 46, 115, 101, 99, 46, 115, 101, 114, 105, 97, 108, 105, 122, 101, 115, 46, 69, 120, 116, 101, 114, 110, 97, 108, 105, 122, 97, 98, 108, 101, 84, 101, 115, 116, -122, 124, 92, -120, -52, 73, -100, 6, 12, 0, 0, 120, 112, 116, 0, 2, 121, 122, 116, 0, 17, 97, 100, 109, 105, 110, 64, 106, 97, 118, 97, 119, 101, 98, 46, 111, 114, 103, 120]
ExternalizableTest类反序列化后的字符串:��sr+com.anbai.sec.serializes.ExternalizableTest�|\��I�xptyztadmin@javaweb.orgx
用户名:yz,邮箱:admin@javaweb.org
```

鉴于两者之间没有多大差别，这里就不再赘述。

### 自定义序列化(writeObject)和反序列化(readObject)

实现了`java.io.Serializable`接口的类还可以定义如下方法(`反序列化魔术方法`)将会在类序列化和反序列化过程中调用：

1. **`private void writeObject(ObjectOutputStream oos)`,自定义序列化。**
2. **`private void readObject(ObjectInputStream ois)`，自定义反序列化。**
3. `private void readObjectNoData()`。
4. `protected Object writeReplace()`，写入时替换对象。
5. `protected Object readResolve()`。

具体的方法名定义在`java.io.ObjectStreamClass#ObjectStreamClass(java.lang.Class<?>)`方法有详细的声明。

**序列化时可自定义的方法示例代码：**

```java
public class DeserializationTest implements Serializable {

/**
	 * 自定义反序列化类对象
	 *
	 * @param ois 反序列化输入流对象
	 * @throws IOException            IO异常
	 * @throws ClassNotFoundException 类未找到异常
	 */
	private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
		System.out.println("readObject...");

		// 调用ObjectInputStream默认反序列化方法
		ois.defaultReadObject();

		// 省去调用自定义反序列化逻辑...
	}

	/**
	 * 自定义序列化类对象
	 *
	 * @param oos 序列化输出流对象
	 * @throws IOException IO异常
	 */
	private void writeObject(ObjectOutputStream oos) throws IOException {
		oos.defaultWriteObject();

		System.out.println("writeObject...");
		// 省去调用自定义序列化逻辑...
	}

	private void readObjectNoData() {
		System.out.println("readObjectNoData...");
	}

	/**
	 * 写入时替换对象
	 *
	 * @return 替换后的对象
	 */
	protected Object writeReplace() {
		System.out.println("writeReplace....");

		return null;
	}

	protected Object readResolve() {
		System.out.println("readResolve....");

		return null;
	}
	
}
```

当我们序列化`DeserializationTest`类时，会自动调用(反射)该类的`writeObject(ObjectOutputStream oos)`方法,反序列化时候也会自动调用`readObject(ObjectInputStream)`方法，也就是说我们可以通过在需要序列化/反序列化的类中定义`readObject`和`writeObject`方法从而实现自定义的序列化和反序列化操作，和当然前提是被序列化的类必须有此方法且方法的修饰符必须是`private`。