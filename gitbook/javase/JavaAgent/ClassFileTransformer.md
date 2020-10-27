# ClassFileTransformer

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
	 * @return 返回一个通过ASM修改后添加了防御代码的字节码byte数组。
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