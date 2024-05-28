# Java反序列化漏洞

`Apache Commons`是`Apache`开源的Java通用类项目在Java中项目中被广泛的使用，`Apache Commons`当中有一个组件叫做`Apache Commons Collections`，主要封装了Java的`Collection(集合)`相关类对象。攻击者利用存在漏洞版本的`Apache Commons Collections`库的反序列化包发送到服务器端进行反序列化操作就会导致服务器被非法入侵。



## 1. RMI服务

为了便于测试反序列化漏洞，这里采用RMI服务作为示例，演示如何攻击一个RMI后端服务，因为RMI的通讯方式就是对象序列化/反序列化。

添加`commons-collections`依赖：

```xml
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>
</dependency>
```

**RMITestInterface.java**

```java
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface RMITestInterface extends Remote {
    String test() throws RemoteException;
}
```

**RMITestImpl.java**

```java
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RMITestImpl extends UnicastRemoteObject implements RMITestInterface {

    private static final long serialVersionUID = 1L;

    protected RMITestImpl() throws RemoteException {
        super();
    }

    public String test() throws RemoteException {
        return "Hello RMI~";
    }

}
```

**RMI服务端：**

```java
import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServerTest {

    // RMI服务器IP地址
    public static final String RMI_HOST = "127.0.0.1";

    // RMI服务端口
    public static final int RMI_PORT = 9527;

    // RMI服务名称
    public static final String RMI_NAME = "rmi://" + RMI_HOST + ":" + RMI_PORT + "/test";

    public static void main(String[] args) {
        try {
            // 注册RMI端口
            LocateRegistry.createRegistry(RMI_PORT);

            // 绑定Remote对象
            Naming.bind(RMI_NAME, new RMITestImpl());

            System.out.println("RMI服务启动成功,服务地址:" + RMI_NAME);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
```

程序运行结果：`RMI服务启动成功,服务地址:rmi://127.0.0.1:9527/test`

**RMI客户端：**

```java
package com.anbai.sec.rmi;

import java.rmi.Naming;

public class RMIClientTest {

    public static void main(String[] args) {
        try {
            // 查找远程RMI服务
            RMITestInterface rt = (RMITestInterface) Naming.lookup("rmi://127.0.0.1:9527/test");

            // 调用远程接口RMITestInterface类的test方法
            String result = rt.test();

            // 输出RMI方法调用结果
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

程序运行结果：`Hello RMI~`

![img](https://oss.javasec.org/images/image-20201113194547079.png)

上述示例演示了一个业务逻辑绝对的简单且安全RMI服务的正常业务流程，但是漏洞并不是出现在业务本身，而是Java的RMI服务和反序列化机制。



## 2. 反序列化攻击

攻击者可以借助RMI协议，发送带有`Apache Commons Collections`反序列化攻击`Payload`的请求到RMI服务端，服务端一旦反序列化RMI客户端的请求就会触发攻击链，最终实现在远程的RMI服务器上执行任意系统命令。

![img](https://oss.javasec.org/images/image-20201113204528201.png)

发送在远程服务器上执行`open -a Calculator.app`（打开计算器）命令的攻击Payload：

![img](https://oss.javasec.org/images/image-20201113205630930.png)

请求成功后在RMI服务端成功的弹出了计算器，攻击成功。



## 3. 反序列化攻击防御

修复反序列化漏洞的常规方法是升级第三方依赖库和JDK版本，或者修改`java.io.ObjectInputStream`类的`resolveClass`和`resolveProxyClass`方法，检测传入的类名是否合法。



### 3.1 升级JDK版本

从`JDK6u141`、`JDK7u131`、`JDK 8u121`开始引入了JEP 290，[JEP 290: Filter Incoming Serialization Data](http://openjdk.java.net/jeps/290)限制了RMI类反序列化，添加了安全过滤机制，在一定程度上阻止了反序列化攻击。

![img](https://oss.javasec.org/images/image-20201113211316664.png)

`ObjectInputStream`在序列化对象时是会调用`java.io.ObjectInputStream#filterCheck`->`sun.rmi.registry.RegistryImpl#registryFilter`，检测合法性：

![img](https://oss.javasec.org/images/image-20201113203150382.png)

当攻击者向一个实现了`JEP 290`的服务端JDK发送反序列化对象时会攻击失败并抛出：`java.io.InvalidClassException: filter status: REJECTED`异常。

![img](https://oss.javasec.org/images/image-20201113201005557.png)

JDK9中`ObjectInputStream`可以设置`ObjectInputFilter`，可实现自定义对象过滤器，如下：

```java
ObjectInputStream ois = new ObjectInputStream(bis);
ois.setObjectInputFilter(new ObjectInputFilter() {
   @Override
   public Status checkInput(FilterInfo filterInfo) {
      // 序列化类名称
      String className = filterInfo.serialClass().getName();

      // 类名检测逻辑
      return ALLOWED;
   }
});
```

除此之外，还可以添加JVM启动参数：`-Djdk.serialFilter`过滤危险的类，参考：[JDK approach to address deserialization Vulnerability](https://access.redhat.com/blogs/766093/posts/3135411)



### 3.2 重写ObjectInputStream类resolveClass

[https://github.com/ikkisoft/SerialKiller](https://github.com/ikkisoft/SerialKiller)是一个非常简单的反序列化攻击检测工具，利用的是继承`ObjectInputStream`重写`resolveClass`方法，为了便于理解，这里把`SerialKiller`改成了直接读取规则的方式检测反序列化的类名。

**示例 - SerialKiller：**

```java
/*
 * 修改自：https://github.com/ikkisoft/SerialKiller
 */
import java.io.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ObjectInputStreamFilter extends ObjectInputStream {

    // 定义禁止反序列化的类黑名单正则表达式
    private static final String[] REGEXPS = new String[]{
            "bsh\\.XThis$", "bsh\\.Interpreter$",
            "com\\.mchange\\.v2\\.c3p0\\.impl\\.PoolBackedDataSourceBase$",
            "org\\.apache\\.commons\\.beanutils\\.BeanComparator$",
            "org\\.apache\\.commons\\.collections\\.Transformer$",
            "org\\.apache\\.commons\\.collections\\.functors\\.InvokerTransformer$",
            "org\\.apache\\.commons\\.collections\\.functors\\.ChainedTransformer$",
            "org\\.apache\\.commons\\.collections\\.functors\\.ConstantTransformer$",
            "org\\.apache\\.commons\\.collections\\.functors\\.InstantiateTransformer$",
            "org\\.apache\\.commons\\.collections4\\.functors\\.InvokerTransformer$",
            "org\\.apache\\.commons\\.collections4\\.functors\\.ChainedTransformer$",
            "org\\.apache\\.commons\\.collections4\\.functors\\.ConstantTransformer$",
            "org\\.apache\\.commons\\.collections4\\.functors\\.InstantiateTransformer$",
            "org\\.apache\\.commons\\.collections4\\.comparators\\.TransformingComparator$",
            "org\\.apache\\.commons\\.fileupload\\.disk\\.DiskFileItem$",
            "org\\.apache\\.wicket\\.util\\.upload\\.DiskFileItem$",
            "org\\.codehaus\\.groovy\\.runtime\\.ConvertedClosure$",
            "org\\.codehaus\\.groovy\\.runtime\\.MethodClosure$",
            "org\\.hibernate\\.engine\\.spi\\.TypedValue$",
            "org\\.hibernate\\.tuple\\.component\\.AbstractComponentTuplizer$",
            "org\\.hibernate\\.tuple\\.component\\.PojoComponentTuplizer$",
            "org\\.hibernate\\.type\\.AbstractType$", "org\\.hibernate\\.type\\.ComponentType$",
            "org\\.hibernate\\.type\\.Type$", "com\\.sun\\.rowset\\.JdbcRowSetImpl$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.builder\\.InterceptionModelBuilder$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.builder\\.MethodReference$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.proxy\\.DefaultInvocationContextFactory$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.proxy\\.InterceptorMethodHandler$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.reader\\.ClassMetadataInterceptorReference$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.reader\\.DefaultMethodMetadata$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.reader\\.ReflectiveClassMetadata$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.reader\\.SimpleInterceptorMetadata$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.spi\\.instance\\.InterceptorInstantiator$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.spi\\.metadata\\.InterceptorReference$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.spi\\.metadata\\.MethodMetadata$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.spi\\.model\\.InterceptionModel$",
            "org\\.jboss\\.(weld\\.)?interceptor\\.spi\\.model\\.InterceptionType$",
            "java\\.rmi\\.registry\\.Registry$", "java\\.rmi\\.server\\.ObjID$",
            "java\\.rmi\\.server\\.RemoteObjectInvocationHandler$",
            "net\\.sf\\.json\\.JSONObject$", "javax\\.xml\\.transform\\.Templates$",
            "org\\.python\\.core\\.PyObject$", "org\\.python\\.core\\.PyBytecode$",
            "org\\.python\\.core\\.PyFunction$", "org\\.mozilla\\.javascript\\..*$",
            "org\\.apache\\.myfaces\\.context\\.servlet\\.FacesContextImpl$",
            "org\\.apache\\.myfaces\\.context\\.servlet\\.FacesContextImplBase$",
            "org\\.apache\\.myfaces\\.el\\.CompositeELResolver$",
            "org\\.apache\\.myfaces\\.el\\.unified\\.FacesELContext$",
            "org\\.apache\\.myfaces\\.view\\.facelets\\.el\\.ValueExpressionMethodExpression$",
            "com\\.sun\\.syndication\\.feed\\.impl\\.ObjectBean$",
            "org\\.springframework\\.beans\\.factory\\.ObjectFactory$",
            "org\\.springframework\\.core\\.SerializableTypeWrapper\\$MethodInvokeTypeProvider$",
            "org\\.springframework\\.aop\\.framework\\.AdvisedSupport$",
            "org\\.springframework\\.aop\\.target\\.SingletonTargetSource$",
            "org\\.springframework\\.aop\\.framework\\.JdkDynamicAopProxy$",
            "org\\.springframework\\.core\\.SerializableTypeWrapper\\$TypeProvider$",
            "java\\.util\\.PriorityQueue$", "java\\.lang\\.reflect\\.Proxy$",
            "javax\\.management\\.MBeanServerInvocationHandler$",
            "javax\\.management\\.openmbean\\.CompositeDataInvocationHandler$",
            "org\\.springframework\\.aop\\.framework\\.JdkDynamicAopProxy$",
            "java\\.beans\\.EventHandler$", "java\\.util\\.Comparator$",
            "org\\.reflections\\.Reflections$"
    };

    public ObjectInputStreamFilter(final InputStream inputStream) throws IOException {
        super(inputStream);
    }

    @Override
    protected Class<?> resolveClass(final ObjectStreamClass serialInput) throws IOException, ClassNotFoundException {
        classNameFilter(new String[]{serialInput.getName()});
        return super.resolveClass(serialInput);
    }

    @Override
    protected Class<?> resolveProxyClass(String[] interfaces) throws IOException, ClassNotFoundException {
        classNameFilter(interfaces);
        return super.resolveProxyClass(interfaces);
    }

    private void classNameFilter(String[] classNames) throws InvalidClassException {
        for (String className : classNames) {
            for (String regexp : REGEXPS) {
                Matcher blackMatcher = Pattern.compile(regexp).matcher(className);

                if (blackMatcher.find()) {
                    throw new InvalidClassException("禁止反序列化的类：" + className);
                }
            }
        }
    }

}
```

调用方式：

```java
// 存在恶意攻击的反序列化类输入流
ByteArrayInputStream bis = new ByteArrayInputStream(bytes);

// 包装原来的ObjectInputStream，校验反序列化类
ObjectInputStream ois = new ObjectInputStreamFilter(bis);

// ObjectInputStream ois = new ObjectInputStream(bis);

// 反序列化
ois.readObject();
```

反序列化包含恶意Payload的输入流时会抛出异常：

![img](https://oss.javasec.org/images/image-20201113222313150.png)

重写ObjectInputStream类方法虽然灵活，但是必须修改每一个需要反序列化输入流的实现类，比较繁琐。



### 3.3 RASP防御反序列化攻击

RASP可以利用动态编辑类字节码的优势，直接编辑`ObjectInputStream`类的`resolveClass/resolveProxyClass`方法字节码，动态插入RASP类代码，从而实现检测反序列化脚本攻击。

```java
package java.io;

public class ObjectInputStream extends InputStream implements ObjectInput, ObjectStreamConstants {
  
    // .. 省略其他代码
        
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            // 插入RASP检测代码，检测ObjectStreamClass反序列化的类名是否合法
    }

    protected Class<?> resolveProxyClass(String[] interfaces) throws IOException, ClassNotFoundException {
            // 插入RASP检测代码，检测动态代理类接口类名是否合法
    }
  
}
```

**RASP防御反序列化攻击流程图：**

![img](https://oss.javasec.org/images/image-20201113211451873.png)

使用RASP检测反序列化攻击，可以不用受制于请求协议、服务、框架等，检测规则可实时更新，从而程度上实现反序列化攻击防御。

**示例 - whoami.jsp：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.codec.binary.Base64" %>
<%@ page import="java.io.ByteArrayInputStream" %>
<%@ page import="java.io.ObjectInputStream" %>
<%
    // 定义一个使用ysoserial生成的执行本地系统命令的Payload：java -jar ysoserial-0.0.6.jar CommonsCollections5 "whoami" |base64
    byte[] classBuffer = Base64.decodeBase64("rO0ABXNyAC5qYXZheC5tYW5hZ2VtZW50LkJhZEF0dHJpYnV0ZVZhbHVlRXhwRXhjZXB0aW9u1Ofaq2MtRkACAAFMAAN2YWx0ABJMamF2YS9sYW5nL09iamVjdDt4cgATamF2YS5sYW5nLkV4Y2VwdGlvbtD9Hz4aOxzEAgAAeHIAE2phdmEubGFuZy5UaHJvd2FibGXVxjUnOXe4ywMABEwABWNhdXNldAAVTGphdmEvbGFuZy9UaHJvd2FibGU7TAANZGV0YWlsTWVzc2FnZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sACnN0YWNrVHJhY2V0AB5bTGphdmEvbGFuZy9TdGFja1RyYWNlRWxlbWVudDtMABRzdXBwcmVzc2VkRXhjZXB0aW9uc3QAEExqYXZhL3V0aWwvTGlzdDt4cHEAfgAIcHVyAB5bTGphdmEubGFuZy5TdGFja1RyYWNlRWxlbWVudDsCRio8PP0iOQIAAHhwAAAAA3NyABtqYXZhLmxhbmcuU3RhY2tUcmFjZUVsZW1lbnRhCcWaJjbdhQIABEkACmxpbmVOdW1iZXJMAA5kZWNsYXJpbmdDbGFzc3EAfgAFTAAIZmlsZU5hbWVxAH4ABUwACm1ldGhvZE5hbWVxAH4ABXhwAAAAUXQAJnlzb3NlcmlhbC5wYXlsb2Fkcy5Db21tb25zQ29sbGVjdGlvbnM1dAAYQ29tbW9uc0NvbGxlY3Rpb25zNS5qYXZhdAAJZ2V0T2JqZWN0c3EAfgALAAAAM3EAfgANcQB+AA5xAH4AD3NxAH4ACwAAACJ0ABl5c29zZXJpYWwuR2VuZXJhdGVQYXlsb2FkdAAUR2VuZXJhdGVQYXlsb2FkLmphdmF0AARtYWluc3IAJmphdmEudXRpbC5Db2xsZWN0aW9ucyRVbm1vZGlmaWFibGVMaXN0/A8lMbXsjhACAAFMAARsaXN0cQB+AAd4cgAsamF2YS51dGlsLkNvbGxlY3Rpb25zJFVubW9kaWZpYWJsZUNvbGxlY3Rpb24ZQgCAy173HgIAAUwAAWN0ABZMamF2YS91dGlsL0NvbGxlY3Rpb247eHBzcgATamF2YS51dGlsLkFycmF5TGlzdHiB0h2Zx2GdAwABSQAEc2l6ZXhwAAAAAHcEAAAAAHhxAH4AGnhzcgA0b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmtleXZhbHVlLlRpZWRNYXBFbnRyeYqt0ps5wR/bAgACTAADa2V5cQB+AAFMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAF4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWVxAH4ABVsAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AMgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+ADJzcQB+ACt1cQB+AC8AAAACcHVxAH4ALwAAAAB0AAZpbnZva2V1cQB+ADIAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAvc3EAfgArdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQABndob2FtaXQABGV4ZWN1cQB+ADIAAAABcQB+ADdzcQB+ACdzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHg=");
    ObjectInputStream bis = new ObjectInputStream(new ByteArrayInputStream(classBuffer));
    bis.readObject();
%>
```

在使用RASP防御的情况下请求示例程序后Java会执行`Runtime.getRuntime().exec("whoami");`，如下图：

![img](https://oss.javasec.org/images/image-20201113225456270.png)

当启动RASP后再次请求示例程序后会发现示例程序已无法正常访问，因为当RASP发现正在反序列化的类存在恶意攻击时候会立即阻断反序列化行为，如下图：

![img](https://oss.javasec.org/images/image-20201113223111183.png)

