# 一、前言

序列化和反序列化的过程中经常会产生漏洞，因为反序列化时通常应用程序会按照相应的规则自动调用某些方法，利用 Java 的多态，攻击者可以进行不同功能类的组合，形成具有攻击手段的调用链，从而造成漏洞。

之前的博客中已经介绍了几种 Java 中存在的反序列化漏洞类型，包括 Java 原生反序列化的利用链的详解（[ysoserial](https://su18.org/post/ysuserial/)）、使用了 Java 原生反序列化进行交互的协议（[RMI](https://su18.org/post/rmi-attack/)）以及对人类来说可读性较强的 json 格式的序列化数据传输（[fastjson](https://su18.org/post/fastjson/)）。

本篇将继续探究基于二进制的协议 Hessian 以及相关的反序列化漏洞利用。

# 二、介绍

Hessian 是 [caucho](https://caucho.com/)  公司的工程项目，为了达到或超过 ORMI/Java JNI 等其他跨语言/平台调用的能力设计而出，在 2004 点发布 1.0 规范，一般称之为 Hessian ，并逐步迭代，在 Hassian jar 3.2.0 之后，采用了新的 2.0 版本的协议，一般称之为 Hessian 2.0。

这是一种动态类型的[二进制序列化](http://hessian.caucho.com/doc/hessian-serialization.html)和 [Web 服务](http://hessian.caucho.com/doc/hessian-ws.html)协议，专为面向对象的传输而设计。Hessian 协议在设计时，重点的几个目标包括了：必须尽可能的快、必须尽可能紧凑、跨语言、不需要外部模式或接口定义等等。

对于这样的设计，caucho 公司其实提供了两种解决方案，一个是 Hession，一个是 Burlap。Hession 是基于二进制的实现，传输数据更小更快，而 Burlap 的消息是 XML 的，有更好的可读性。两种数据都是基于 HTTP 协议传输。

Hessian 本身作为 [Resin](https://caucho.com/products/resin) 的一部分，但是它的 `com.caucho.hessian.client` 和 `com.caucho.hessian.server` 包不依赖于任何其他的 Resin 类，因此它也可以使用任何容器如 Tomcat 中，也可以使用在 EJB 中。事实上很多通讯框架都使用或支持了这个规范来序列化及反序列化类。

作为一个二进制的序列化协议，Hessian 自行定义了一套自己的储存和还原数据的机制。对 8 种基础数据类型、3 种递归类型、ref 引用以及 Hessian 2.0 中的内部引用映射进行了相关定义。这样的设计使得 Hassian 可以进行跨语言跨平台的调用。

其他更多关于 Hessian 的介绍可以在官网看到，接下来看下 Hessian 的使用。

# 三、基本使用

因为 Hessian 基于 HTTP 协议，所以通常通过 Web 应用来提供服务，以下为几种常见的模式。

## 基于 Servlet 项目

通过把提供服务的类注册成 Servlet 的方式来作为 Server 端进行交互。

![](https://oss.javasec.org/images/1650934576284.png)

服务端需要有一个该方法的具体实现，这里通过使该类继承自 `com.caucho.hessian.server.HessianServlet` 来将其标记为一个提供服务的 Servlet ：

![](https://oss.javasec.org/images/1650934675668.png)

在 `web.xml` 中配置 Servlet 的映射。

![](https://oss.javasec.org/images/1650935933223.png)

Client 端通过  `com.caucho.hessian.client.HessianProxyFactory` 工厂类创建对接口的代理对象，并进行调用，可以看到调用后执行了服务端的逻辑并返回了代码。

![](https://oss.javasec.org/images/1650938036639.png)

除了将具体实现类继承自 HessianServlet 之外，还可以不继承，完全通过配置文件进行设置，将待调用的接口和类作为 HessianServlet 的初始化参数进行配置：

![](https://oss.javasec.org/images/1650944418913.png)

`web.xml` 配置如下。

![](https://oss.javasec.org/images/1650938432215.png)


## 整合 Spring 项目

Spring-web 包内提供了 `org.springframework.remoting.caucho.HessianServiceExporter` 用来暴露远程调用的接口和实现类。使用该类 export 的 Hessian Service 可以被任何 Hessian Client 访问，因为 Spring 中间没有进行任何特殊处理。

从 spring-web-5.3 后，该类被标记为 `@Deprecated` ， 也就是说 spring 在逐渐淘汰对基于序列化的远程调用的相关支持。

![](https://oss.javasec.org/images/1650948136857.png)

Spring 的配置方式种类就太多了，基于配置文件的可以看 spring 官方文档上的[这篇文章](https://docs.spring.io/spring-framework/docs/3.0.0.M4/reference/html/ch19s03.html)，基于代码和注解的可以查看[这篇文章](https://www.baeldung.com/spring-remoting-hessian-burlap)。

由于本人喜欢使用注解这种方式，并且对 xml 极度厌恶，所以此处采用注解方式进行测试，如下图。

![](https://oss.javasec.org/images/1650952391546.png)

配置后依旧使用同样的 Client 代码访问即可。

![](https://oss.javasec.org/images/1650952443099.png)

## 自封装调用

除了配合 web 项目使用外，也可以自行封装自行调用，通过对 `HessianInput/HessianOutput`、`Hessian2Input/Hessian2Output`、`BurlapInput/BurlapOutput` 的相关方法的封装，可以自行实现传输、存储等逻辑，使用 Hessian 进行序列化和反序列化数据。

比较常见的封装成如下的工具类自行调用:

![](https://oss.javasec.org/images/1650943305812.png)


## JNDI 源

Hessian 还可以通过将 HessianProxyFactory 配置为 JNDI Resource 的方式来调用。

例如在 `resin.xml` 中添加如下配置：

![](https://oss.javasec.org/images/1650972801210.png)

然后使用 JNDI 查询的方法调用，调用代码如下：

```java
Context ic = new InitialContext();
Greeting hello = (Greeting) ic.lookup("java:comp/env/hessian/jndi");
HashMap<String, String> o = new HashMap<String, String>();
o.put("a", "c");
System.out.println("Hello: " + hello.sayHello(o));
```

其他使用依赖注入等相关配置的内容可以查看[这篇文章](http://smc.siinsan.gob.gt/resin-doc/examples/hessian-ioc/index.xtp)，这里就不再重复了，感觉使用频次较低。


# 四、源码浅析

在看本章前，希望各位读者已经跟着上面的铺垫自行搭建项目进行尝试，并自行将调用参数改为各种数据类型、自定义类等等进行感受。

在源码上，Hessian 的框架模型要比 RMI 的设计简单的多，而且很多思路都是类似的，这里主要分几个部分来分析一下。

这里在分析源码时，将使用文章编写时的最新版 4.0.66 进行学习，使用不同版本可能有所差异，请注意。

## 接口的暴露与访问

首先来说下**Servlet**。

在 Servlet 中采用继承或配置的时候，都是 `com.caucho.hessian.server.HessianServlet` 类在起作用，这个类是一个 `javax.servlet.http.HttpServlet` 的子类。这说明这个类的 `init` 方法将会承担一些初始化的功能，而 `service` 方法将会是相关处理的起始位置。

接下来重点关注这两个方法。首先是 `init` 方法，这个方法总体来讲就是用来初始化 HessianServlet 的成员变量，包括 `_homeAPI`(调用类的接口 Class)、`_homeImpl`(具体实现类的对象)、`_serializerFactory`(序列化工厂类)、`_homeSkeleton`(封装方法)等等。

![](https://oss.javasec.org/images/1651031014032.png)

基础逻辑如下：

![](https://oss.javasec.org/images/1651035644027.png)

这里有一个小细节，Hessian 自行封装了一个 `loadClass`  方法加载类，优先从线程中获取类加载器加载类，在没有设置的情况下使用当前类加载器加载。

![](https://oss.javasec.org/images/1650981349908.png)

类加载的知识学着学着就忘记了，不知道为什么要这样写，所以看到这里特意和园长语音了一下，思考了一下，觉得大概有两种原因：
- 不同环境下可能使用自定义类加载器重新加载类，对原来的代码进行魔改，这里可以确保拿到原本的代码。
- 线程中一般默认是 AppClassLoader，是加载用户代码的类加载器，通常可以很快找到用户的类。

接下来看下 `service` 方法，

![](https://oss.javasec.org/images/1651037726744.png)

`invoke` 方法根据 objectID 是否为空决定调用哪个。

![](https://oss.javasec.org/images/1651037762217.png)

接下来就进入 `com.caucho.hessian.server.HessianSkeleton` 的调用流程，先来简单了解一下这个类。HessianSkeleton 是 AbstractSkeleton 的子类，用来对 Hessian 提供的服务进行封装。

首先 AbstractSkeleton 初始化时接收调用接口的类型，并按照自己的逻辑把接口中的方法保存在 `_methodMap` 中，包括“方法名”、“方法名__方法参数个数”、“方法名_参数类型_参数2类型”等自定义格式。

![](https://oss.javasec.org/images/1651043998890.png)

HessianSkeleton 初始化时将实现类保存在成员变量 `_service` 中。

![](https://oss.javasec.org/images/1651045336561.png)

HessianSkeleton 中还有两个成员变量，`HessianFactory` 用来创建 HessianInput/HessianOutput 流，`HessianInputFactory` 用来读取和创建 HessianInput/Hessian2Input 流，用到的时候会细说。

![](https://oss.javasec.org/images/1651046335624.png)

简单了解了之后，来看下调用中的关键方法 `HessianSkeleton#invoke` ，首先是输入输出流的创建。

![](https://oss.javasec.org/images/1651047768394.png)

然后主要是调用方法的查找和参数的反序列化，反序列化后进行反射调用，并写回结果。

![](https://oss.javasec.org/images/1651050697331.png)


接下来说下 **Spring**。 

在 Spring 中的关键类是 `org.springframework.remoting.caucho.HessianExporter`，关键方法是 `doInvoke` 方法，其实逻辑与 Servlet 类似，就不多重复了。

![](https://oss.javasec.org/images/1651052914588.png)

可以看到这里也是额外处理了一下类加载器的问题。

## 序列化与反序列化流程

Hessian 的序列化反序列化流程有几个关键类，一般包括输入输出流、序列化/反序列化器、相关工厂类等等，依次来看一下。

首先是输入和输出流，Hessian 定义了 AbstractHessianInput/AbstractHessianOutput 两个抽象类，用来提供序列化数据的读取和写入功能。Hessian/Hessian2/Burlap 都有这两个类各自的实现类来实现具体的逻辑。

先来看**序列化**，对于输出流关键类为 AbstractHessianOutput 的相关子类，这些类都提供了 `call` 等相关方法执行方法调用，`writeXX` 方法进行序列化数据的写入，这里以 `Hessian2Output` 为例。

除了基础数据类型，主要关注的是对 Object 类型数据的写入方法 `writeObject`：

![](https://oss.javasec.org/images/1651062358378.png)

这个方法根据指定的类型获取序列化器 `Serializer` 的实现类，并调用其 `writeObject` 方法序列化数据。在当前版本中，可看到一共有 29 个子类针对各种类型的数据。对于自定义类型，将会使用 `JavaSerializer/UnsafeSerializer/JavaUnsharedSerializer` 进行相关的序列化动作，默认情况下是 `UnsafeSerializer`。

![](https://oss.javasec.org/images/1651062885396.png)

`UnsafeSerializer#writeObject` 方法兼容了 Hessian/Hessian2 两种协议的数据结构，会调用 `writeObjectBegin` 方法开始写入数据，

![](https://oss.javasec.org/images/1651063977126.png)

`writeObjectBegin` 这个方法是 AbstractHessianOutput 的方法，Hessian2Output 重写了这个方法，而其他实现类没有。也就是说在 Hessian 1.0 和 Burlap 中，写入自定义数据类型（Object）时，都会调用 `writeMapBegin` 方法将其标记为 Map 类型。

![](https://oss.javasec.org/images/1651064508602.png)

在 Hessian 2.0 中，将会调用 `writeDefinition20` 和 `Hessian2Output#writeObjectBegin` 方法写入自定义数据，就不再将其标记为 Map 类型。

再看**反序列化**，对于输入流关键类为 AbstractHessianInput 的子类，这些类中的 `readObject` 方法定义了反序列化的关键逻辑。基本都是长达 200 行以上的 switch case 语句。在读取标识位后根据不同的数据类型调用相关的处理逻辑。这里还是以 Hessian2Input 为例。

![](https://oss.javasec.org/images/1651055458287.png)

与序列化过程设计类似，Hessian 定义了 Deserializer 接口，并为不同的类型创建了不同的实现类。这里重点看下对自定义类型对象的读取。

在 Hessian 1.0 的 HessianInput 中，没有针对 Object 的读取，而是都将其作为 Map 读取，在序列化的过程中我们也提到，在写入自定义类型时会将其标记为 Map 类型。

![](https://oss.javasec.org/images/1651067540081.png)

`MapDeserializer#readMap` 方法提供了针对 Map 类型数据的处理逻辑。

![](https://oss.javasec.org/images/1651067141512.png)

在 Hessian 2.0 中，则是提供了 `UnsafeDeserializer` 来对自定义类型数据进行反序列化，关键方法在 `readObject` 处。

![](https://oss.javasec.org/images/1651068010709.png)

`instantiate` 使用 unsafe 实例的 `allocateInstance` 直接创建类实例。

![](https://oss.javasec.org/images/1651067999672.png)


## 远程调用

在远程调用时，我们的代码如下：

```java
String url = "http://localhost:8080/hessian";
HessianProxyFactory factory  = new HessianProxyFactory();
Greeting            greeting = (Greeting) factory.create(Greeting.class, url);
HashMap map = new HashMap<String,String>();
map.put("a","d");
System.out.println("Hello: " + greeting.sayHello(map));
```

可以看到，这里创建了 HessianProxyFactory 实例，并调用其 `create` 方法，这里实际上是使用了 Hessian 提供的 HessianProxy 来为待调用的接口和 HessianRemoteObject 创建动态代理类。

![](https://oss.javasec.org/images/1651068959915.png)

我们知道动态代理对象无论调用什么方法都会走 `InvocationHandler` 的 invoke 方法。

![](https://oss.javasec.org/images/1651069337128.png)

发送请求获取结果并反序列化，这里使用了 `HessianURLConnection` 来建立连接。

![](https://oss.javasec.org/images/1651069346185.png)

非常简单的逻辑，就是发出了一个 HTTP 请求并反序列化数据而已。

## 一些细节

### 协议版本

在之前已经介绍过了，Hessian 传输协议已经由 1.0 版本迭代到了 2.0 版本。但是目前的 Hessian 包是两种协议都支持的，并且服务器使用哪种协议读取序列化数据，和返回哪种协议格式的序列化数据，将完全由请求中的标志位来进行定义。

在我们测试使用的最新版中，这一设定位于 `HessianProxyFactory` 中的两个布尔型变量中，即 `_isHessian2Reply` 和 `_isHessian2Request`，如下图，默认情况下，客户端使用 Hessian 1.0 协议格式发送序列化数据，服务端使用 Hessian 2.0 协议格式返回序列化数据。

![](https://oss.javasec.org/images/1651108246902.png)

如果想自己指定用 Hessian 2.0 协议进行传输，可以使用如下代码进行设置：

```java
HessianProxyFactory factory  = new HessianProxyFactory();
factory.setHessian2Request(true);
```

### Serializable

在 Java 原生反序列化中，实现了 `java.io.Serializable` 接口的类才可以反序列化。Hessian 象征性的支持了这种规范，具体的逻辑如下图，在获取默认序列化器时，判断了类是否实现了 Serializable 接口。

![](https://oss.javasec.org/images/1651114475710.png)

但同时 Hessian 还提供了一个 `_isAllowNonSerializable` 变量用来打破这种规范，可以使用 `SerializerFactory#setAllowNonSerializable` 方法将其设置为 true，从而使未实现 Serializable 接口的类也可以序列化和反序列化。

这就很魔幻了，判断是在序列化的过程中进行的，而非反序列化过程，那自然可以绕过了，换句话说，Hessian 实际支持反序列化任意类，无需实现 Serializable 接口。

这里在提一下 serialVersionUID 的问题，在 Java 原生反序列化中，在未指定 serialVersionUID 的情况下如果修改过类中的方法和属性，将会导致反序列化过程中生成的 serialVersionUID 不一致导致的异常，但是 Hessian 并不关注这个字段，所以即使修改也无所谓。

然后是 transient 和 static 的问题，在序列化时，由 `UnsafeSerializer#introspect` 方法来获取对象中的字段，在老版本中应该是 `getFieldMap` 方法。依旧是判断了成员变量标识符，如果是 transient 和 static 字段则不会参与序列化反序列化流程。

![](https://oss.javasec.org/images/1651116817595.png)

在原生流程中，标识为 transient 仅代表不希望 Java 序列化反序列化这个对象，开发人员可以在 `writeObject/readObject` 中使用自己的逻辑写入和恢复对象，但是 Hessian 中没有这种机制，因此标识为 transient 的字段在反序列化中一定没有值的。

### Object Naming

之前在看代码时看到过，Hessian 在调用时还支持使用 id 和 ejbid 参数，可以导致调用不同的实体 Beans。

这种情况当 Hessian 支持的调用服务是一些面向对象的服务比如 naming services/entity beans/session beans 或 EJB 容器时可以使用。

本质上的调用流程都是一样的，只是提供服务的对象有所不同。

相关内容可以查看官方连接：[http://hessian.caucho.com/...#ObjectNamingnon-normative](http://hessian.caucho.com/doc/hessian-1.0-spec.xtp#ObjectNamingnon-normative)

# 五、漏洞

可以看到， Hessian 协议使用 unsafe 创建类实例，使用反射写入值，并且没有在重写了某些方法后对其进行调用这样的逻辑。

所以无论是构造方法、getter/setter 方法、readObject 等等方法都不会在 Hessian 反序列化中被触发，那怎么会产生漏洞呢？

答案就在 Hessian 对 Map 类型数据的处理上，在之前的分析中提到，`MapDeserializer#readMap` 对 Map 类型数据进行反序列化操作是会创建相应的 Map 对象，并将 Key 和 Value 分别反序列化后使用 put 方法写入数据。在没有指定 Map 的具体实现类时，将会默认使用 HashMap ，对于 SortedMap，将会使用 TreeMap。

而众所周知， HashMap 在 put 键值对时，将会对 key 的 hashcode 进行校验查看是否有重复的 key 出现，这就将会调用 key 的 hasCode 方法，如下图。

![](https://oss.javasec.org/images/1651123884314.png)

而 TreeMap 在 put 时，由于要进行排序，所以要对 key 进行比较操作，将会调用 compare 方法，会调用 key 的 compareTo 方法。

![](https://oss.javasec.org/images/1651213661427.png)

也就是说 Hessian 相对比原生反序列化的利用链，有几个限制：
- kick-off chain 起始方法只能为 hashCode/equals/compareTo 方法；
- 利用链中调用的成员变量不能为 transient 修饰；
- 所有的调用不依赖类中 readObject 的逻辑，也不依赖 getter/setter 的逻辑。

这几个限制也导致了很多 Java 原生反序列化利用链在 Hessian 中无法使用，甚至 ysoserial 中一些明明是 hashCode/equals/compareTo 触发的链子都不能直接拿来用。

# 六、利用链

目前常见的 Hessian 利用链在 [marshalsec](https://github.com/mbechler/marshalsec) 中共有如下五个：
- Rome
- XBean
- Resin
- SpringPartiallyComparableAdvisorHolder
- SpringAbstractBeanFactoryPointcutAdvisor

也就是抽象类 `marshalsec.HessianBase` 分别实现的 5 个接口。
![](https://oss.javasec.org/images/1650882733394.png)

触发漏洞的触发点对应在 HessianBase 的三个实现类：Hessian\Hessian2\Burlap。接下来我们依次看一下这些调用链。

这里由于篇幅原因（懒癌），这里就不一一分析各个利用链了，只是大概说一下利用链和一些关键触发点，详细的利用测试代码和注释已经更新到 [ysoserial](https://github.com/su18/ysoserial) 学习项目中。

## Rome

Rome 的链核心是 ToStringBean，这个类的 `toString` 方法会调用他封装类的全部无参 getter 方法，所以可以借助 `JdbcRowSetImpl#getDatabaseMetaData()` 方法触发 JNDI 注入。

![](https://oss.javasec.org/images/1651135533586.png)

![](https://oss.javasec.org/images/1651135509258.png)

外层用 EqualsBean 和 HashMap 封装，反序列化调用 `EqualsBean#hashCode()` 触发 ToStringBean。

![](https://oss.javasec.org/images/1651135625039.png)

这是一个 Rome 经典触发点，在 ysoserial 中也见过这个逻辑。

### 二次反序列化

上面 Gadget 因为是 JNDI 需要出网，所以通常被认为限制很高，因此还需要找无需出网的利用方式。其中一个常见的方式是使用 `java.security.SignedObject` 进行二次反序列化。

这个类有个 getObject 方法会从流里使用原生反序列化读取数据，就造成了二次反序列化。

![](https://oss.javasec.org/images/1651139384898.png)

逻辑很清楚，无需多言，直接封装 ysoserial 中的 ROME 反序列化链即可。

### 命令执行

在 y4tacker 师傅的博客中，提到了利用 `sun.print.UnixPrintService` 直接执行命令的方式，

这个类有诸多 get 方法，通过拼接字符串的方式执行系统命令。

![](https://oss.javasec.org/images/1651142700263.png)

也是非常直观，可以直接利用。但只可惜这个类在高版本被移除，并仅支持 Unix/类Unix 操作系统。

这里 UnixPrintService 接口是没有实现 Serializable 接口的，就需要之前提到过的绕过手段，marshalsec 中使用了自定义 SerializerFactory 类。

![](https://oss.javasec.org/images/1651146693622.png)

通过 `setAllowNonSerializable` 方法修改后，指定给序列化流对象就可以了。

![](https://oss.javasec.org/images/1651146775183.png)

实际上不需要这么麻烦，序列化时一行代码就解决了：

```java
oo.getSerializerFactory().setAllowNonSerializable(true);
```

## Resin

Resin 这条利用链的入口点实际上是 HashMap 对比两个对象时触发的 `com.sun.org.apache.xpath.internal.objects.XString` 的 `equals` 方法。

使用 XString 的 equals 方法触发 `com.caucho.naming.QName` 的 toSting 方法。

![](https://oss.javasec.org/images/1651154876527.png)

QName 实际上是 Resin 对上下文 Context 的一种封装，它的 toString 方法会调用其封装类的 `composeName` 方法获取复合上下文的名称。

![](https://oss.javasec.org/images/1651155579747.png)

这条利用链使用了 `javax.naming.spi.ContinuationContext` 类，其 `composeName` 方法调用 `getTargetContext` 方法，然后调用 `NamingManager#getContext` 方法传入其成员变量 CannotProceedException 的相关属性。

漏洞触发点在 `NamingManager#getObjectInstance` 方法，这个方法调用 VersionHelper 加载类并实例化。

![](https://oss.javasec.org/images/1651159006194.png)

加载时使用了 URLClassLoader 并指定了类名和 codebase。

![](https://oss.javasec.org/images/1651159023947.png)

这个逻辑就赋予了程序远程加载类的功能，也就是漏洞的最终利用点。

![](https://oss.javasec.org/images/1651160418027.png)


## XBean

XBean 这条链几乎是与 Resin 一模一样，只不过是在 XBean 中找到了类似功能的实现。

首先还是用 XString 触发 `ContextUtil.ReadOnlyBinding` 的 toString 方法（实际继承 `javax.naming.Binding`），toString 方法调用 getObject 方法获取对象。

![](https://oss.javasec.org/images/1651163590272.png)

调用 `ContextUtil#resolve` 方法。

![](https://oss.javasec.org/images/1651163564869.png)

方法调用 `NamingManager#getObjectInstance` 方法，后续触发逻辑一致，从远程加载恶意类字节码。

![](https://oss.javasec.org/images/1651163362200.png)

成功弹出计算器。

![](https://oss.javasec.org/images/1651164795087.png)

## Spring AOP

这条利用链也很简单，还是利用 HashMap 对比触发 equals 方法，核心是 AbstractPointcutAdvisor 和其子类 AbstractBeanFactoryPointcutAdvisor。

触发点在 AbstractPointcutAdvisor 的 `equals` 方法，对比两个 AbstractPointcutAdvisor 是否相同，就是在对比其 Pointcut 切点和 Advice 是否为同一个。

![](https://oss.javasec.org/images/1651207387125.png)

其子类 AbstractBeanFactoryPointcutAdvisor 是和 BeanFactory 有关的 PointcutAdvisor，简单来说就是进行切片时可以使用 beanFactory 里面注册的实例。其 `getAdvice` 方法会调用其成员变量 beanFactory 的 `getBean` 方法获取 Bean 实例。

![](https://oss.javasec.org/images/1651206599878.png)

这时只要结合 SimpleJndiBeanFactory 就可以触发 JNDI 查询。

![](https://oss.javasec.org/images/1651206567544.png)

配合工具弹出计算器。

![](https://oss.javasec.org/images/1651205826995.png)

## Spring Context & AOP

这条链的触发点在于 AspectJAwareAdvisorAutoProxyCreator$PartiallyComparableAdvisorHolder 的 `toString` 方法，会打印 order 属性，调用 advisor 的 `getOrder` 方法。

![](https://oss.javasec.org/images/1651226518210.png)

此时就需要找到类同时实现了 Advisor 和 Ordered 接口，于是找到了 AspectJPointcutAdvisor ，这个类的 `getOrder` 方法调用 AbstractAspectJAdvice 的 `getOrder` 方法。

![](https://oss.javasec.org/images/1651227077569.png)

又调用了 AspectInstanceFactory 的  `getOrder` 方法。

![](https://oss.javasec.org/images/1651227189610.png)

继续找 AspectInstanceFactory 的子类看有没有可以触发的点，找到了 BeanFactoryAspectInstanceFactory，其 `getOrder` 方法调用 beanFactory 的 `getType` 方法。

![](https://oss.javasec.org/images/1651226416998.png)

于是又掏出 SimpleJndiBeanFactory ，他的的 `doGetType` 方法调用 `doGetSingleton` 方法执行 JNDI 查询，组成了完整的利用链。

![](https://oss.javasec.org/images/1651226311692.png)

在 marshalsec 封装对象时，使用了 HotSwappableTargetSource 封装类，其 equals 方法会调用其 target 的 equals 方法。

![](https://oss.javasec.org/images/1651220074314.png)

其实并无必要，感觉是纯炫技写法。

![](https://oss.javasec.org/images/1651220324923.png)


## Groovy

在 wh1t3p1g 师傅的 ysomap 项目中，还添加了 Groovy 的利用链，结合了在 ysoserial 中的 Groovy 链所使用的 ConvertedClosure 动态代理 MethodClosure 反射调用的能力和 Resin 利用链中 ContinuationDirContext 远程加载类的执行点。

触发点使用了 TreeMap 触发 compareTo 方法，使用 ConvertedClosure 生成动态代理对象，将方法调用转移至 MethodClosure 封装类，借用其 doCall 方法进一步调用 `ContinuationDirContext#listBindings` 方法触发后续的攻击流程。

![](https://oss.javasec.org/images/1651216237802.png)

如果看过 ysoserial 和 之前的 Resin 链，这条链很好理解。

![](https://oss.javasec.org/images/1651216914313.png)


## 其他

在 ysoserial 中，除了 Rome，还有 URLDNS、Hibernate、Myfaces、Clojure、AspectJWeaver 等链的触发点使用了 hashCode 方法，至于其能否作为 Hessian 利用链，这里就不一一尝试了。

很多触发都可以通过动态代理等方式串联起来。有兴趣的朋友可以尝试自行拼接和挖掘，关于自动化利用链的挖掘，可以参考我之前写的[高效挖掘反序列化漏洞——GadgetInspector改造](https://su18.org/post/gadgetor/)，这里挖掘 Hessian 链的时候 Source 点可以简单的设置为重写了 hashCode/equals/compareTo 的方法。

相信一定还是存在非常多可用的 Hessian 反序列化链的。

# 七、衍生项目

由于 Hessian 协议设计的特性，有很多分布式框架使用了该协议进行传输，如 
[xxl-rpc](https://github.com/xuxueli/xxl-rpc)、[sofa-rpc](https://github.com/sofastack/sofa-rpc)等。

并且还有项目在原 Hessian 协议基础上进行增强和改进，例如 Alibaba 的 [hessian-lite](https://github.com/apache/dubbo-hessian-lite) 和蚂蚁金服的 [sofa-hessian](https://github.com/sofastack/sofa-hessian) 等。

这些衍生项目的细节有所不同，但是大框架还是脱离不了原有的 Hessian 协议，也就同样的会受到反序列化攻击的风险。由于大同小异，这里也不再分析衍生项目历史上报过的漏洞和 CVE 了。

还有一点需要注意的是，在 sofa-hessian 项目里，提供了 Hessian 反序列化防御的一种思路，维护了一个黑名单，在反序列化之前进行 filter 操作，有相关需求的朋友可以参考一下。

https://github.com/sofastack/sofa-hessian/blob/master/src/main/resources/security/serialize.blacklist

![](https://oss.javasec.org/images/1651144285493.png)

> 


# 八、参考

[http://hessian.caucho.com/](http://hessian.caucho.com/)

[https://developer.aliyun.com/article/31862](https://developer.aliyun.com/article/31862)

[http://blog.orange.tw/](http://blog.orange.tw/2020/09/how-i-hacked-facebook-again-mobileiron-mdm-rce.html)

[https://y4tacker.github.io/](https://y4tacker.github.io/2022/03/21/year/2022/3/2022%E8%99%8E%E7%AC%A6CTF-Java%E9%83%A8%E5%88%86/#%E5%88%A9%E7%94%A8%E4%B8%80%EF%BC%9ASignedObject%E5%AE%9E%E7%8E%B0%E4%BA%8C%E6%AC%A1%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96)

[http://124.223.185.138/index.php/archives/23.html](http://124.223.185.138/index.php/archives/23.html)

[https://f002.backblazeb2.com](https://f002.backblazeb2.com/file/sec-news-backup/files/writeup/blog.csdn.net/_u011721501_article_details_79443598/index.html)

[https://zhuanlan.zhihu.com/p/44787200](https://zhuanlan.zhihu.com/p/44787200)

[https://www.mi1k7ea.com/](https://www.mi1k7ea.com/2020/01/25/Java-Hessian%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/)

[https://github.com/wh1t3p1g/ysomap](https://github.com/wh1t3p1g/ysomap)