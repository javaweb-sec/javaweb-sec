# 浅谈被动式IAST产品与技术实现-代码实现Demo篇

## 实现IAST所需要的一些技术
通过之前一篇文章，大家应该已经了解到了当前IAST的一些基础知识，如果想要从零实现一个被动式的IAST，我们至少需要掌握关于字节码操作的技术，比如ASM、Javassist等，如果不想从零实现或从那么底层的方式去实现，可以试试看使用AspectJ技术，或者结合使用开源的APM框架进行改造，让其成为一个简单的被动IAST。

本次所涉及的Demo源码已经公开，地址为[JAVA_IAST_EXAMPLE](https://github.com/iiiusky/java_iast_example)。

## 实验环境搭建

这次IAST相关的环境其实和之前的RASP环境基本差不多。大家可以参照之前的[浅谈RASP技术攻防之实战[环境配置篇]](https://www.03sec.com/Ideas/qian-tanrasp-ji-shu-gong-fang-zhi-shi-zhan-huan-ji.html#morphing)文章内容去搭建一个本地的实验环境，唯一变的，可能就是包名了。

## demo整体逻辑

这次实验的整体逻辑如果相比真正的IAST，肯定会有很多缺少的细节部分完善，所以仅仅适合用来学习了解被动IAST实现的大致流程，整体逻辑图如下:

![](https://oss.javasec.org/images/16394506343329.jpg)



从上图可以看到，其实在这次demo实现的过程中，逻辑也并不是很复杂，大致文字版说明如下：

```
http->enterHttp->enterSource->leaveSource

enterPropagator->leavePropagator(…………此过程重复n次…………)

enterSink->leaveSink(可省略)->leaveHttp
```
以上大致完成了整个污点跟踪链路流程，在初始化HTTP的时候，将新建一个`LinkedList<CallChain>`类型的对象，用来存储线程链路调用的数据。

为了方便对不同类型的点进行适配，抽象了一个`Handler`出来，然后在根据不同的类型实现具体的`ClassVisitorHandler`内容,`Handler.java`具体代码如下:
```java
package cn.org.javaweb.iast.visitor;

import org.objectweb.asm.MethodVisitor;

/**
 * @author iiusky - 03sec.com
 */
public interface Handler {

	MethodVisitor ClassVisitorHandler(MethodVisitor mv, final String className, int access, String name, String desc, String signature, String[] exceptions);
}

```


## 实现Http埋点
在Java EE中通过劫持`javax.servlet.Servlet`的`service`方法和`javax.servlet.Filter`类的`doFilter`方法不但可以获取到原始的`HttpServletRequest`和`HttpServletResponse`对象，还可以控制Servlet和Filter的程序执行逻辑。

可以将所有参数描述符为`(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V`的方法进行插入埋点，并缓存request、response对象。

实现的代码如下（示例代码为了便于理解未考虑异常处理）:

```java
package cn.org.javaweb.iast.visitor.handler;

import cn.org.javaweb.iast.visitor.Handler;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;

import java.lang.reflect.Modifier;


/**
 * @author iiusky - 03sec.com
 */
public class HttpClassVisitorHandler implements Handler {

	private static final String METHOD_DESC = "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V";

	public MethodVisitor ClassVisitorHandler(MethodVisitor mv, final String className, int access,
	                                         String name, String desc, String signature, String[] exceptions) {
		if ("service".equals(name) && METHOD_DESC.equals(desc)) {
			final boolean isStatic = Modifier.isStatic(access);
			final Type    argsType = Type.getType(Object[].class);

			System.out.println(
					"HTTP Process 类名是: " + className + ",方法名是: " + name + "方法的描述符是：" + desc + ",签名是:"
							+ signature + ",exceptions:" + exceptions);
			return new AdviceAdapter(Opcodes.ASM5, mv, access, name, desc) {
				@Override
				protected void onMethodEnter() {
					loadArgArray();
					int argsIndex = newLocal(argsType);
					storeLocal(argsIndex, argsType);
					loadLocal(argsIndex);

					if (isStatic) {
						push((Type) null);
					} else {
						loadThis();
					}
					loadLocal(argsIndex);
					mv.visitMethodInsn(INVOKESTATIC, "cn/org/javaweb/iast/core/Http", "enterHttp",
							"([Ljava/lang/Object;)V", false);

				}

				@Override
				protected void onMethodExit(int i) {
					super.onMethodExit(i);
					mv.visitMethodInsn(INVOKESTATIC, "cn/org/javaweb/iast/core/Http", "leaveHttp", "()V",
							false);
				}
			};
		}
		return mv;
	}
}
```

上面的代码将对所有实现**javax.servlet.Servlet#service**的方法进行了埋点处理(接口、抽象类除外)，真正编译到jvm中的类如下:
![](https://oss.javasec.org/images/16393858968816.jpg)
可以看到，在对进入方法的时候调用了IAST中的方法`cn.org.javaweb.iast.core.Http#enterHttp`，在离开方法的时候，调用了`cn.org.javaweb.iast.core.Http#leaveHttp`
其中`enterHttp`具体代码如下:
```java
public static void enterHttp(Object[] objects) {
    if (!haveEnterHttp()) {
      IASTServletRequest request = new IASTServletRequest(objects[0]);
      IASTServletResponse response = new IASTServletResponse(objects[1]);

      RequestContext.setHttpRequestContextThreadLocal(request, response, null);
    }
  }
```
从上文中可以看到，传入的`HttpServletRequest`和`HttpServletResponse`对象存到了当前线程的上下文中，方便后续对数据的调取使用。

`leaveHttp`具体代码如下:
```java
public static void leaveHttp() {
    IASTServletRequest request = RequestContext.getHttpRequestContextThreadLocal()
        .getServletRequest();
    System.out.printf("URL            : %s \n", request.getRequestURL().toString());
    System.out.printf("URI            : %s \n", request.getRequestURI().toString());
    System.out.printf("QueryString    : %s \n", request.getQueryString().toString());
    System.out.printf("HTTP Method    : %s \n", request.getMethod());
    RequestContext.getHttpRequestContextThreadLocal().getCallChain().forEach(item -> {
      if (item.getChainType().contains("leave")) {
        String returnData = null;
        if (item.getReturnObject().getClass().equals(byte[].class)) {
          returnData = new String((byte[]) item.getReturnObject());
        } else if (item.getReturnObject().getClass().equals(char[].class)) {
          returnData = new String((char[]) item.getReturnObject());
        } else {
          returnData = item.getReturnObject().toString();
        }

        System.out
            .printf("Type: %s CALL Method Name: %s CALL Method Return: %s \n", item.getChainType(),
                item.getJavaClassName() + item.getJavaMethodName(), returnData);
      } else {
        System.out
            .printf("Type: %s CALL Method Name: %s CALL Method Args: %s \n", item.getChainType(),
                item.getJavaClassName() + item.getJavaMethodName(),
                Arrays.asList(item.getArgumentArray()));
      }
    });
  }
```
其实就是从当前线程中获取到在调用`enterHttp`时候存的数据，然后对其中的数据进行可视化的输出打印。

## 实现Source埋点
在Java EE中通过可以劫持获取输入源的所有方法，比如常用的`getParameter`、`getHeader`等类似的方法，在这里将对调用的方法、以及返回的参数进行跟踪，这里为真正污点跟踪的起点。可以简单的理解为就是http各个get方法即为来源，但这一结论不保证完全适配所有情况。
对于Source相关的点处理的代码如下（示例代码为了便于理解未考虑异常处理）:

```java
package cn.org.javaweb.iast.visitor.handler;

import cn.org.javaweb.iast.visitor.Handler;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;

import java.lang.reflect.Modifier;


/**
 * @author iiusky - 03sec.com
 */
public class SourceClassVisitorHandler implements Handler {

	private static final String METHOD_DESC = "(Ljava/lang/String;)Ljava/lang/String;";

	public MethodVisitor ClassVisitorHandler(MethodVisitor mv, final String className, int access, final String name,
	                                         final String desc, String signature, String[] exceptions) {
		if (METHOD_DESC.equals(desc) && "getParameter".equals(name)) {
			final boolean isStatic = Modifier.isStatic(access);

			System.out.println("Source Process 类名是: " + className + ",方法名是: " + name + "方法的描述符是：" + desc + ",签名是:" + signature + ",exceptions:" + exceptions);
			return new AdviceAdapter(Opcodes.ASM5, mv, access, name, desc) {
				@Override
				protected void onMethodEnter() {
					loadArgArray();
					int argsIndex = newLocal(Type.getType(Object[].class));
					storeLocal(argsIndex, Type.getType(Object[].class));
					loadLocal(argsIndex);
					push(className);
					push(name);
					push(desc);
					push(isStatic);

					mv.visitMethodInsn(INVOKESTATIC, "cn/org/javaweb/iast/core/Source", "enterSource", "([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V", false);
					super.onMethodEnter();
				}

				@Override
				protected void onMethodExit(int opcode) {
					Type returnType = Type.getReturnType(desc);
					if (returnType == null || Type.VOID_TYPE.equals(returnType)) {
						push((Type) null);
					} else {
						mv.visitInsn(Opcodes.DUP);
					}
					push(className);
					push(name);
					push(desc);
					push(isStatic);
					mv.visitMethodInsn(INVOKESTATIC, "cn/org/javaweb/iast/core/Source", "leaveSource", "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V", false);
					super.onMethodExit(opcode);
				}
			};
		}
		return mv;
	}
}

```
其实以上代码的逻辑，只是简单的对于`getParameter`进行了埋点处理，让其调用IAST的处理逻辑，编译到JVM的Class内容如下：
![](https://oss.javasec.org/images/16393858968837.jpg)

可以看到，在进入方法后调用了`cn.org.javaweb.iast.core.Source#enterSource`，具体内容如下
```java
public static void enterSource(Object[] argumentArray,
	                               String javaClassName,
	                               String javaMethodName,
	                               String javaMethodDesc,
	                               boolean isStatic) {
		if (haveEnterHttp()) {
			CallChain callChain = new CallChain();
			callChain.setChainType("enterSource");
			callChain.setArgumentArray(argumentArray);
			callChain.setJavaClassName(javaClassName);
			callChain.setJavaMethodName(javaMethodName);
			callChain.setJavaMethodDesc(javaMethodDesc);
			callChain.setStatic(isStatic);
			RequestContext.getHttpRequestContextThreadLocal().addCallChain(callChain);
		}
	}
```
其实就是对参数、类名、方法名、描述符等信息添加到了callChain中.
在方法结束前获取了返回值，并且调用了`cn.org.javaweb.iast.core.Source#leaveSource`方法，将返回值传入了进去，那么在处理的时候，就将其结果放到了`callChain.returnObject`。

![](https://oss.javasec.org/images/16393858968856.jpg)

## 实现Propagator埋点
传播点的选择是非常关键的，传播点规则覆盖的越广得到的传播链路就会更清晰。比如简单粗暴的对`String`、`Byte`等类进行埋点，因为中间调用这些类的太多了,所以可能导致一个就是结果堆栈太长，不好对调用链进行分析，但是对于传播点的选择，可以更精细化一些去做选择，比如`Base64`的`decode`、`encode`也可以作为传播点进行埋点，以及执行命令的`java.lang.Runtime#exec`也是可以作为传播点的，因为最终执行命令是最底层在不同系统封装的调用执行命令JNI方法的类，如`java.lang.UNIXProcess`等，所以将`java.lang.Runtime#exec`作为传播点也是一个选择。为了方便演示污点传播的效果，对`Base64`的`decode`以及`encode`和`java.lang.Runtime`进行了埋点处理，具体实现代码如下（示例代码为了便于理解未考虑异常处理）:

```java
package cn.org.javaweb.iast.visitor.handler;

import cn.org.javaweb.iast.visitor.Handler;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;

import java.lang.reflect.Modifier;


/**
 * @author iiusky - 03sec.com
 */
public class PropagatorClassVisitorHandler implements Handler {

	private static final String METHOD_DESC = "(Ljava/lang/String;)[B";

	private static final String CLASS_NAME = "java.lang.Runtime";

	@Override
	public MethodVisitor ClassVisitorHandler(MethodVisitor mv, final String className, int access,
	                                         final String name, final String desc, String signature, String[] exceptions) {
		if ((name.contains("decode") && METHOD_DESC.equals(desc)) || CLASS_NAME.equals(className)) {
			final boolean isStatic = Modifier.isStatic(access);
			final Type    argsType = Type.getType(Object[].class);

			if (((access & Opcodes.ACC_NATIVE) == Opcodes.ACC_NATIVE) || className
					.contains("cn.org.javaweb.iast")) {
				System.out.println(
						"Propagator Process Skip  类名:" + className + ",方法名: " + name + "方法的描述符是：" + desc);
			} else {
				System.out
						.println("Propagator Process 类名:" + className + ",方法名: " + name + "方法的描述符是：" + desc);
				return new AdviceAdapter(Opcodes.ASM5, mv, access, name, desc) {
					@Override
					protected void onMethodEnter() {
						loadArgArray();
						int argsIndex = newLocal(argsType);
						storeLocal(argsIndex, argsType);
						loadLocal(argsIndex);
						push(className);
						push(name);
						push(desc);
						push(isStatic);

						mv.visitMethodInsn(INVOKESTATIC, "cn/org/javaweb/iast/core/Propagator",
								"enterPropagator",
								"([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V",
								false);
						super.onMethodEnter();
					}

					@Override
					protected void onMethodExit(int opcode) {
						Type returnType = Type.getReturnType(desc);
						if (returnType == null || Type.VOID_TYPE.equals(returnType)) {
							push((Type) null);
							
						} else {
							mv.visitInsn(Opcodes.DUP);
						}
						push(className);
						push(name);
						push(desc);
						push(isStatic);
						mv.visitMethodInsn(INVOKESTATIC, "cn/org/javaweb/iast/core/Propagator",
								"leavePropagator",
								"(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V",
								false);
						super.onMethodExit(opcode);
					}
				};
			}
		}
		return mv;
	}
}

```
真正运行在JVM中的类如下:
`java.util.Base64$Decoder#decode`

![](https://oss.javasec.org/images/16393858968879.jpg)


`java.lang.Runtime`
![](https://oss.javasec.org/images/16393858968898.jpg)

可以看到其实也是在方法进入后和方法离开前插入了IAST的代码逻辑，以便可以直观的观察到入参值以及返回值发生的变化。

## 实现Sink埋点

对于Sink点的选择，其实和找RASP最终危险方法的思路一致，只限找到危险操作真正触发的方法进行埋点即可，比如`java.lang.UNIXProcess#forkAndExec`方法，这种给`java.lang.UNIXProcess#forkAndExec`下点的方式太底层，如果不想这么底层，也可以仅对`java.lang.ProcessBuilder#start`方法或者`java.lang.ProcessImpl#start`进行埋点处理。本次实验选择了对`java.lang.ProcessBuilder#start`进行埋点处理，具体实现代码如下（示例代码为了便于理解未考虑异常处理）:

```java
package cn.org.javaweb.iast.visitor.handler;

import cn.org.javaweb.iast.visitor.Handler;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;

import java.lang.reflect.Modifier;


/**
 * @author iiusky - 03sec.com
 */
public class SinkClassVisitorHandler implements Handler {

	private static final String METHOD_DESC = "()Ljava/lang/Process;";

	@Override
	public MethodVisitor ClassVisitorHandler(MethodVisitor mv, final String className, int access,
	                                         final String name, final String desc, String signature, String[] exceptions) {
		if (("start".equals(name) && METHOD_DESC.equals(desc))) {
			final boolean isStatic = Modifier.isStatic(access);
			final Type    argsType = Type.getType(Object[].class);

			System.out.println("Sink Process 类名:" + className + ",方法名: " + name + "方法的描述符是：" + desc);
			return new AdviceAdapter(Opcodes.ASM5, mv, access, name, desc) {
				@Override
				protected void onMethodEnter() {
					loadArgArray();
					int argsIndex = newLocal(argsType);
					storeLocal(argsIndex, argsType);
					loadThis();
					loadLocal(argsIndex);
					push(className);
					push(name);
					push(desc);
					push(isStatic);

					mv.visitMethodInsn(INVOKESTATIC, "cn/org/javaweb/iast/core/Sink", "enterSink",
							"([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V",
							false);
					super.onMethodEnter();
				}
			};
		}
		return mv;
	}
}

```
在这次实验中，选择了对所有方法名为`start`且方法描述为`()Ljava/lang/Process;`的类进行埋点，其实也就是对`java.lang.ProcessBuilder#start`进行埋点处理。
最终运行在JVM中的class如下：

![](https://oss.javasec.org/images/16393858968915.jpg)

可以看到在方法进去后调用了IAST的`cn.org.javaweb.iast.core.Sink#enterSink`方法，以此来确定一个调用链是否已经到达危险函数执行点。对于Sink，除了整体处理逻辑与`Propagator`以及`Source`相似，多了一个`setStackTraceElement`的操作，目的是将在触发`Sink`点的堆栈将其保存下来，方便后面使用分析。
具体代码如下

```java
public static void enterSink(Object[] argumentArray,
	                             String javaClassName,
	                             String javaMethodName,
	                             String javaMethodDesc,
	                             boolean isStatic) {
		if (haveEnterHttp()) {
			CallChain callChain = new CallChain();
			callChain.setChainType("enterSink");
			callChain.setArgumentArray(argumentArray);
			callChain.setJavaClassName(javaClassName);
			callChain.setJavaMethodName(javaMethodName);
			callChain.setJavaMethodDesc(javaMethodDesc);
			callChain.setStatic(isStatic);
			callChain.setStackTraceElement(Thread.currentThread().getStackTrace());
			RequestContext.getHttpRequestContextThreadLocal().addCallChain(callChain);
		}
	}
```

## 结果验证
全部实现完成后，写一个jsp来执行命令试试看，代码如下:
> 该JSP接收一个参数，然后对该参数进行base64解码后传入Runtime.exec中来执行命令，最后输出执行结果
```java
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Base64" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<pre>
<%
    String sb = request.getParameter("cmd");
    byte[] decode = Base64.getDecoder().decode(sb);
    Process process = Runtime.getRuntime().exec(new String(decode));
    InputStream in = process.getInputStream();
    int a = 0;
    byte[] b = new byte[1024];

    while ((a = in.read(b)) != -1) {
        out.println(new String(b, 0, a));
    }

    in.close();
%>
</pre>
```
接着编译agent，将其加入到tomcat的启动命令中，部署jsp页面，访问看看结果
![](https://oss.javasec.org/images/16393858968933.jpg)

可以看到，首先触发了`getParameter`方法中的Source埋点，传入的参数为`cmd`，获取到的结果为`CHdK`，接着连续触发了5次Propagator点。

第一次触发的Propagator点位`Base64`类中`decode`方法，传入的参数是`CHdK`，返回值为`pwd`(原始返回为[]byte,为了方便展示，对其转为了字符串)，这时候已经可以初步看到了参数的获取到base64解码，也就是原始source点已经发生了变化。

第二次触发的埋点信息为获取一个`Runtime`对象，调用的是`java.lang.Runtime#getRuntime`,传入的参数为空，返回的结果为一个Runtime的对象信息，其实就是实例化了一个`java.lang.Runtime`对象，这次可以观察到一个小细节，就是这个返回对象发生了变化，但是并没有传入任何参数。
![](https://oss.javasec.org/images/16393858968949.jpg)

第三次触发的埋点信息为调用`java.lang.Runtime#exec`方法(接收参数类型为:`String`)，传入的值是`pwd`，在这次调用中可以看到，第一次Propagator点的返回值作为了入参传入了这次调用，但是紧接着并触发没有想象中的`leavePropagator`方法，而是调用了另一个`exec`方法。
![](https://oss.javasec.org/images/16393858968964.jpg)
第四次触发的埋点信息为调用`java.lang.Runtime#exec`方法(接收参数类型为:`String、String[]、File`)，其中第一个参数的值为`pwd`，而其它参数为`null`(本文不讨论如何确定第几个参数是污染点的问题，这个可以通过加规则去逐步完善)。在这次调用中可以看到，第三次中传递过来的`pwd`没有发生变化，然而也没有触发`leavePropagator`方法，由此可以推测出来这个方法内部继续调用了在规则里面预先匹配到的方法。
![](https://oss.javasec.org/images/16393858968979.jpg)

第五次触发的埋点信息为调用`java.lang.Runtime#exec`方法(接收参数类型为:`String[]、String[]、File`)，传入的值是`[[Ljava.lang.String;@58ed07d8, null, null] `，这时候就看到了在传入的值由`pwd`变为了一个`String`数组类型的对象，返回到第四次触发的埋点看，其实就可以看到`var`6其实是最开始是由`var1`，也就是入参值`pwd`转换得到的。然后可以看到在当前调用的方法里面，又调用了规则中的Sink点（`java.lang.ProcessBuilder#start`）方法。
![](https://oss.javasec.org/images/16393858968993.jpg)

以上就是大概从Srouce点(`getParameter`)，经过中间的Propagator点(`java.util.Base64$Decoder#decode、java.lang.Runtime#getRuntime、java.lang.Runtime#exec`)到最终Sink点(`java.lang.ProcessBuilder#start`)的整体大概流程了。

## 总结

在本次实验中，将`java.lang.Runtime`作为了传播点，其实在整体流程访问结束后，这个传播点才会有返回值返回回来，他是在传播的过程中调用到了Sink点。
![](https://oss.javasec.org/images/16393858969006.jpg)

那么对于这种情况，是否应该摒弃将`java.lang.Runtime`作为传播点呢？这其实应该就是仁者见仁智者见智了，对于整体IAST的流程，其实和RASP流程差不多，但是对于传播点的选择，目前大家更多的是基于规则(正则or继承类)判断去覆盖其中的传播链，或者更简单粗暴的对`String`、`Byte`进行埋点，但是需要处理的细节也就更多了，以及对于在整条链路中的无用调用也需要处理。是否有一种一劳永逸的办法可以完整的拿到整条污点传播链路，从而抛弃基于规则的对传播点进行人为覆盖，这个可能就需要进行更加深入的研究了。

在这次实现的demo中，并没有结合真正业务去实现，以及IAST的其它功能点去展开研究，比如流量重放、SCA、污点在方法中的参数位置等功能。如果仅仅是想融入DevSecOps中，可以基于开源的APM项目实现一个简易的IAST，根据具体的一些公司开发规范，去定制一些规则点，来减少因为某些问题导致的误报情况。


## 参考链接
- https://www.03sec.com/Ideas/qian-tanrasp-ji-shu-gong-fang-zhi-shi-zhan-huan-ji.html
