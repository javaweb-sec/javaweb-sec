# Tomcat AJP 协议

AJP（Apache JServer Protocol) 协议最初是由 Gal Shachor 设计。对于Web服务器与Servlet容器通信来讲，最主要目的是：

- 提高性能（主要是速度）。
- 添加对SSL的支持。

目前Tomcat中使用的版本均为AJP1.3，简称为ajp13。ajp13协议是面向数据包的。出于对性能的考虑，选择了以二进制格式传输，而不是更易读的纯文本。

Web服务器通过TCP连接与servlet容器进行通信。为了减少昂贵的套接字（socket）创建过程，web服务器将尝试保持与servlet容器的持久的TCP连接，并为多个请求/响应周期重复使用一个连接。

官方文档位置：https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html

在Tomcat的`server.xml` 中默认配置了两种连接器：

![img](https://oss.javasec.org/images/image-20200925172240547.png)

一种是使用的HTTP Connector，监听8080端口，还有一个AJP Connector，监听了8009端口。在Tomcat中这个协议的监听的一直都是默认开启的。

AJP Connector 的配置文档：http://tomcat.apache.org/tomcat-6.0-doc/config/ajp.html

AJP Connector 可以通过 AJP 协议和另一个 web 容器进行交互。例如正常情况下的访问是由客户端通过HTTP协议访问到Tomcat服务器返回结果，此时将由HTTP Connector处理请求，但也可以使用通过AJP协议来进行访问，此时将由AJP Connector来处理。

但是通常情况下用户的客户端并不会支持AJP协议，因此想要使用AJP协议进行访问，需要自己实现连接器，或由中间的代理服务器进行转发。

- Apache HTTP Server 2.x 上的启用 AJP 的 mod_proxy 模块（在 2.2 上已成为默认配置模块）
- 其他任何支持 JK 1.2.x 的服务器



## AJP 协议配置

测试环境：

- 操作系统：CentOS 7
- Web服务器：Apache/2.4.6
- JSP服务器：Tomcat 9.0.27
- JDK：1.8.0_251

### mod_jk

Mod_JK是Apache的一个模块，其通过AJP协议实现Apache与Tomcat之间的通讯

官网地址：http://tomcat.apache.org/download-connectors.cgi

使用手册：http://tomcat.apache.org/connectors-doc/webserver_howto/apache.html

由于配置较 mod_proxy_ajp 复杂，此处不进行演示，有兴趣的朋友可以按照官方文档自行尝试。



### mod_proxy_ajp

首先在 `/conf/httpd.conf` 中添加模块：

```conf
LoadModule proxy_ajp_module modules/mod_proxy_ajp.so
```

在虚拟主机中设置代理转发

```apache2
<VirtualHost *:81>
    ProxyPass / ajp://localhost:8009/
    ProxyPassReverse / ajp://localhost:8009/
</VirtualHost>
```

正常启动Tomcat，把我们命令执行的 `test.jsp` 放在ROOT中，使用8080端口正常以HTTP协议直接访问项目：

![img](https://oss.javasec.org/images/image-20200927182058312.png)

使用 apache 监听的 81 端口进行 AJP 协议转发也可以正常访问：

![img](https://oss.javasec.org/images/image-20200927182041920.png)




## AJP协议数据包处理

在看AJP协议数据包处理之前，先来了解一下Tomcat处理一个请求的过程。大致如下流程：

![img](https://oss.javasec.org/images/image-20201013113437489.png)

一次请求的处理可以划分为Connector及Container进行处理，经历的过程大致如下：

- 一个TCP/IP数据包发送到目标服务器，被监听此端口的Tomcat获取到。
- 处理这个Socket网络连接，使用Processor解析及包装成request和response对象，并传递给下一步处理。
- Engine来处理接下来的动作，匹配虚拟主机Host、上下文Context、Mapping Table中的servlet。
- Servlet调用相应的方法（service/doGet/doPost...）进行处理，并将结果逐级返回。

而对于使用HTTP协议或AJP协议进行访问的请求来讲，在解析包装成为request和response对象之后的流程都是一样的，主要的区别就是对socket流量的处理以及使用Processor进行解析的过程的不同。

提供这部分功能的接口为 `org.apache.coyote.Processor<S>` ，主要负责请求的预处理。并通过它将请求转发给Adapter，针对不用的协议则具有不同的实现类。

这个接口里定义了一些重要的方法：

![img](https://oss.javasec.org/images/image-20201013120233058.png)

这里主要还是针对于HTTP协议和AJP协议，抽象类`AbstractProcessorLight`及其子类` AbstractProcessor`还是对共有特性的封装。

![img](https://oss.javasec.org/images/image-20201013120649828.png)

` AbstractProcessor`具有三个子类，`AjpProcessor` 用来处理AJP协议，`Http11Processor` 用来处理HTTP/1.1，`StreamProcessor`用来处理HTTP/2，我们先来看看针对平常使用的HTTP协议的处理。

`Http11Processor` 重点的`process()`方法，使用`service() `方法来处理标准HTTP请求，这里我们重点看一下：

解析请求行和请求头部分：

![img](https://oss.javasec.org/images/image-20201013150323668.png)

在Tomcat 8.5 之后，加入了判断是否需要HTTP协议升级：

![img](https://oss.javasec.org/images/image-20201013145153619.png)

调用`prepareRequest()`，将相关信息放入`Http11InputBuffer`对象中

![img](https://oss.javasec.org/images/image-20201013150607226.png)

然后调用Adapter将请求交给Container处理：

![img](https://oss.javasec.org/images/image-20201013145055762.png)

然后接下来是一些收尾工作。在了解了这个过程后，我们再来看一下 `AjpProcessor` 中`service()`方法，大体上是一致的流程，只是具体的细节不同，首先是一些解析数据包读取字节的操作，这里不是重点，暂且不提，然后也是调用 `prepareRequest()` 方法进行预处理：

![img](https://oss.javasec.org/images/image-20201013155203542.png)

处理之后同样的调用Adapter将请求交给Container处理

![img](https://oss.javasec.org/images/image-20201014141337514.png)

而AJP协议的任意文件读取/任意文件包含漏洞，则出现在上面提到的 `prepareRequest()` 方法中。



## AJP漏洞

在 `AjpProcessor` 的 `prepareRequest()` 中，恶意攻击者可通过控制请求内容，为request对象任意的设置属性。

在`switch/case` 判断中,当`attributeCode=10` 时，将调用 `request.setAttribute` 方法存入。

![img](https://oss.javasec.org/images/image-20201013155520803.png)

所以在此攻击者拥有了可控的点，这个点该如何利用呢？

### DefaultServlet

在`$CATALINA_BASE/conf/web.xml` 中默认配置了如下内容：

![img](https://oss.javasec.org/images/image-20201013165533770.png)

可以看到这是一个默认的Servlet，这个 `DefaultServlet` 服务于全部应用，当客户端请求不能匹配其他所有Servlet时，将由此Servlet处理，主要用来处理静态资源。使用 `serveResource()` 方法提供资源文件内容：

![img](https://oss.javasec.org/images/image-20201013170955488.png)

会调用 `getRelativePath()` 方法获取请求资源路径：

![img](https://oss.javasec.org/images/image-20201013171255971.png)

这个方法存在一个判断，如图中红框位置标出：如果 `request.getAttribute()` 中`javax.servlet.include.request_uri` 不为空，则会取 `javax.servlet.include.path_info` 和`javax.servlet.include.servlet_path` 的值，并进行路径拼接，返回路径结果。

这个结果 path 会被带入到 `getResource()` 方法中返回结果，只要文件存在，即可读取其中内容。

![img](https://oss.javasec.org/images/image-20201013171943132.png)

由此可见，配合AJP协议中的缺陷，可以控制attribute中的内容，造成任意文件读取漏洞。

但是需要注意的是，在读取资源文件的过程中，会调用`org.apache.tomcat.util.http.RequestUtil.normalize()` 方法来对路径的合法性进行校验，如果存在 `./` 或 `../` 则会返回 `null` ，在后续流程中会抛出一个非法路径的异常终止文件读取操作。

![img](https://oss.javasec.org/images/image-20201014110343428.png)

因此我们无法使用 `../` 跳出目录，只能读取Web应用目录下的文件。



### JspServlet

同样的在`$CATALINA_BASE/conf/web.xml` 中，对访问以 `.jsp/*.jspx` 后缀结尾的请求，调用 `JspServlet` 处理请求。

![img](https://oss.javasec.org/images/image-20201014101016408.png)

看一下重点的 `service()`，代码如下图，在attribute中含有如下 `javax.servlet.include.servlet_path`，`javax.servlet.include.path_info` 时，将会取出并拼接为文件路径 `jspUri`。

![img](https://oss.javasec.org/images/image-20201014102154103.png)

拼接成 `jspUri` 后，调用 `serviceJspFile()` ，将此文件解析为jsp文件并执行。

![img](https://oss.javasec.org/images/image-20201014104235407.png)

因此这就构成了一个文件包含漏洞。在文件内容可控的情况下，就可以延伸为任意代码执行漏洞，所以网上有的分析文章也出现了任意代码执行、任意命令执行漏洞的字眼。



## AJP客户端

在了解了AJP协议的漏洞成因之后，我们只需要构造一个客户端就可以实现自己的攻击行为了。

AJP协议的请求和响应包结构在文档可以看到：https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html

实现过程这里不进行描述，代码放在如下位置，请自行观看：

```
javaweb-sec/javaweb-sec-source/javasec-test/javasec-tomcat-ajp
```

在这里进行漏洞两种利用方式的演示。

### Web目录任意文件读取

任意文件读取需要满足的条件是：

- 访问的地址（target）是一个没有 Servlet 映射的地址
- request_uri 属性不为空
- servlet_path 和 path_info 拼接得到我们想要读取的文件

如下图配置：

![img](https://oss.javasec.org/images/image-20201014190817620.png)

可以看到成功返回了文件内容：

![img](https://oss.javasec.org/images/image-20201014191218553.png)



### JSP文件包含

假设我们在web目录下具有可控的文件，比如我们上传了一个`aaa.jpg`，文件里是一个执行`whoami`命令并返回结果的jsp恶意文件。

![img](https://oss.javasec.org/images/image-20201014184822525.png)

这是我们需要控制的是访问的地址（target）是一个`.jsp`结尾的文件，并且 servlet_path、path_info 拼接起来是我们可控的文件路径。

![img](https://oss.javasec.org/images/image-20201014185022126.png)

运行返回结果，可以看到我们的 jpg 文件以 jsp 解析并执行成功：

![img](https://oss.javasec.org/images/image-20201014190642641.png)




## 问题拓展

在实际对Tomcat AJP 漏洞的研究和利用过程中，逐渐产生了以下几个问题，请自行思考：

- SpringBoot项目是否受到此漏洞影响？如果能受到影响，是在什么情况下？
- Struts2、Shiro、SpringMVC 等等具有一些全局过滤器的情况下，是否能够触发漏洞？
- jsp 作为视图模板时是否存在漏洞？

参考答案链接：https://www.colabug.com/2020/0318/7137788/