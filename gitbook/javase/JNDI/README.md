# JNDI

`JNDI(Java Naming and Directory Interface)`是Java提供的`Java 命名和目录接口`。通过调用`JNDI`的`API`应用程序可以定位资源和其他程序对象。`JNDI`是`Java EE`的重要部分，需要注意的是它并不只是包含了`DataSource(JDBC 数据源)`，`JNDI`可访问的现有的目录及服务有:`JDBC`、`LDAP`、`RMI`、`DNS`、`NIS`、`CORBA`。

**Naming Service 命名服务：**

命名服务将名称和对象进行关联，提供通过名称找到对象的操作，例如：DNS系统将计算机名和IP地址进行关联、文件系统将文件名和文件句柄进行关联等等。

**Directory Service 目录服务：**

目录服务是命名服务的扩展，除了提供名称和对象的关联，**还允许对象具有属性**。目录服务中的对象称之为目录对象。目录服务提供创建、添加、删除目录对象以及修改目录对象属性等操作。

**Reference 引用**

在一些命名服务系统中，系统并不是直接将对象存储在系统中，而是保持对象的引用。引用包含了如何访问实际对象的信息。

更多`JNDI`相关概念参考: [Java技术回顾之JNDI：命名和目录服务基本概念](https://blog.csdn.net/ericxyy/article/details/2012287)

## JNDI目录服务注册

访问`JNDI`目录服务时会通过预先设置好环境变量访问对应的服务， 如果创建`JNDI`上下文(`Context`)时未指定`环境变量`对象，`JNDI`会自动搜索`系统属性(System.getenv())`、`applet 参数`和`应用程序资源文件(jndi.properties)`。

**[JNDI 查找及其关联的引用](https://docs.oracle.com/cd/E19957-01/819-1553/jndi.html):**

| JNDI 查找名称               | 关联的引用                      |
| --------------------------- | ------------------------------- |
| `java:comp/env`             | 应用程序环境项                  |
| `java:comp/env/jdbc`        | JDBC 数据源资源管理器连接工厂   |
| `java:comp/env/ejb`         | EJB 引用                        |
| `java:comp/UserTransaction` | UserTransaction 引用            |
| `java:comp/env/mail`        | JavaMail 会话连接工厂           |
| `java:comp/env/url`         | URL 连接工厂                    |
| `java:comp/env/jms`         | JMS 连接工厂和目标              |
| `java:comp/ORB`             | 应用程序组件之间共享的 ORB 实例 |

**使用`JNDI`创建目录服务对象代码片段：**

```java
// 创建环境变量对象
Hashtable env = new Hashtable();

// 设置JNDI初始化工厂类名
env.put(Context.INITIAL_CONTEXT_FACTORY, "类名");

// 设置JNDI提供服务的URL地址
env.put(Context.PROVIDER_URL, "url");

// 创建JNDI目录服务对象
DirContext context = new InitialDirContext(env);
```

`Context.INITIAL_CONTEXT_FACTORY(初始上下文工厂的环境属性名称)`指的是`JNDI`服务处理的具体类名称，如：`DNS`服务可以使用`com.sun.jndi.dns.DnsContextFactory`类来处理，`JNDI`上下文工厂类必须实现`javax.naming.spi.InitialContextFactory`接口，通过重写`getInitialContext`方法来创建服务。

**javax.naming.spi.InitialContextFactory:**

```java
package javax.naming.spi;

public interface InitialContextFactory {

	public Context getInitialContext(Hashtable<?,?> environment) throws NamingException;
	
}
```

## JNDI-DNS解析

`JNDI`支持访问`DNS`服务，注册环境变量时设置`JNDI`服务处理的工厂类为`com.sun.jndi.dns.DnsContextFactory`即可。

**com.sun.jndi.dns.DnsContextFactory代码片段：**

```java
package com.sun.jndi.dns;

public class DnsContextFactory implements InitialContextFactory {
  
  // 获取处理DNS的JNDI上下文对象
  public Context getInitialContext(Hashtable<?, ?> var1) throws NamingException {
    if (var1 == null) {
      var1 = new Hashtable(5);
    }

    return urlToContext(getInitCtxUrl(var1), var1);
  }
  
  // 省去其他无关方法和变量
}
```

**使用JNDI解析DNS测试：**

```java
package com.anbai.sec.jndi;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

/**
 * Creator: yz
 * Date: 2019/12/23
 */
public class DNSContextFactoryTest {

   public static void main(String[] args) {
      // 创建环境变量对象
      Hashtable env = new Hashtable();

      // 设置JNDI初始化工厂类名
      env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");

      // 设置JNDI提供服务的URL地址，这里可以设置解析的DNS服务器地址
      env.put(Context.PROVIDER_URL, "dns://223.6.6.6/");

      try {
         // 创建JNDI目录服务对象
         DirContext context = new InitialDirContext(env);

         // 获取DNS解析记录测试
         Attributes attrs1 = context.getAttributes("baidu.com", new String[]{"A"});
         Attributes attrs2 = context.getAttributes("qq.com", new String[]{"A"});

         System.out.println(attrs1);
         System.out.println(attrs2);
      } catch (NamingException e) {
         e.printStackTrace();
      }
   }

}
```

程序运行结果：

```
{a=A: 39.156.69.79, 220.181.38.148}
{a=A: 125.39.52.26, 58.247.214.47, 58.250.137.36}
```

## JNDI-RMI远程方法调用

**使用JNDI解析调用远程RMI方法测试：**

```java
package com.anbai.sec.jndi;

import com.anbai.sec.rmi.RMITestInterface;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.rmi.RemoteException;
import java.util.Hashtable;

import static com.anbai.sec.rmi.RMIServerTest.*;

/**
 * Creator: yz
 * Date: 2019/12/24
 */
public class RMIRegistryContextFactoryTest {

   public static void main(String[] args) {
      String providerURL = "rmi://" + RMI_HOST + ":" + RMI_PORT;

      // 创建环境变量对象
      Hashtable env = new Hashtable();

      // 设置JNDI初始化工厂类名
      env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");

      // 设置JNDI提供服务的URL地址
      env.put(Context.PROVIDER_URL, providerURL);

      // 通过JNDI调用远程RMI方法测试，等同于com.anbai.sec.rmi.RMIClientTest类的Demo
      try {
         // 创建JNDI目录服务对象
         DirContext context = new InitialDirContext(env);

         // 通过命名服务查找远程RMI绑定的RMITestInterface对象
         RMITestInterface testInterface = (RMITestInterface) context.lookup(RMI_NAME);

         // 调用远程的RMITestInterface接口的test方法
         String result = testInterface.test();

         System.out.println(result);
      } catch (NamingException e) {
         e.printStackTrace();
      } catch (RemoteException e) {
         e.printStackTrace();
      }
   }

}
```

程序执行结果：

```
Hello RMI~
```



