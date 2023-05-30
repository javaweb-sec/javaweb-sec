# 前言

本系列第三篇文章，记录 s2-045/s2-046/S2-048/s2-052/s2-053/s2-055 的调试过程。

# S2-045

Multipart 处理 Content-Type 出现异常时，将会对异常信息进行 OGNL 解析导致安全漏洞。

> 影响版本：Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-045
> 描述：基于 Jakarta Multipart 解析器执行文件上传时可能导致 RCE。

为了实现上传文件一类的功能，我们通常使用 POST 方法，MIME 类型设置为 `multipart/form-data` 的数据包，这种情况下，服务器端需要对此类请求进行解析。但是 Struts2 没有提供自己的请求解析器，它不会处理相关的请求，它会调用其他的上传框架来进行解析完成这个功能。

这里使用了 2.5.10 版本进行演示，在 default.properties 文件中，配置了 MIME 类型为 `multipart/form-data` 的解析器为 jakarta。

![img](https://oss.javasec.org/images/1625284296508.png)

通过注释我们可以看到这个解析器还可以配置为 cos/pell/jakarta-stream 等。

在一次 multipart 请求到 Struts2 时，会在经过 FileUploadInterceptor 拦截器时被处理，我们从头来看一下处理流程：

1. Struts2 使用 `StrutsPrepareFilter#doFilter` 预处理和封装请求，会调用 `org.apache.struts2.dispatcher.Dispatcher#wrapRequest` 方法处理，如果 Content-Type 包含 multipart/form-data 字样，将创建 MultiPartRequestWrapper 对象用来封装 request 对象，这里请注意，判断 Content-Type 使用的是字符串的 contains 方法。
   
![img](https://oss.javasec.org/images/1625284296510.png)

2. Struts2 在 `Dispatcher.multipartHandlerName` 中注入了配置文件中配置的 `struts.multipart.parser`，并使用 `getMultiPartRequest` 方法创建 MultiPartRequest 实例，在默认配置下，是 JakartaMultiPartRequest 对象。
   
![img](https://oss.javasec.org/images/1625284296512.png)

3. 创建 MultiPartRequestWrapper 方法时，会调用 MultiPartRequest 实例的 `parse()` 方法，解析后将 MultiPartRequest 中产生的 errors 取出并放入 wrapper 中的 errors 中，或者在处理过程中抛出的异常，也会放在 errors 中。
  
![img](https://oss.javasec.org/images/1625284296516.png)

4. MultiPartRequest 的 `parse()` 方法，会调用 `this.setLocale()` 和 `this.processUpload()` 方法处理上传请求，在处理过程中产生的异常捕获后会经过 `buildErrorMessage()` 处理后添加到 this.errors 中。
   
![img](https://oss.javasec.org/images/1625284296520.png)

5. 预处理结束后，将会调用拦截器栈依次处理请求，当经过 FileUploadInterceptor 时，会对 multipart 请求进行相关处理：判断当前请求 request 对象是否为 MultiPartRequestWrapper 实例，如果不是将会 return，也就是说判断当前请求是不是一次 multipart 请求。
   
![img](https://oss.javasec.org/images/1625284296524.png)

6. 将 request 强转为 MultiPartRequestWrapper 对象，使用 `hasErrors()` 判断这个 request 对象中是否含有报错信息，如果有的话，将使用 `LocalizedTextUtil.findText()` 对错误信息进行国际化处理，并添加到 action 对象中。
   
![img](https://oss.javasec.org/images/1625284296527.png)

7. 处理这次文件上传的内容，从下面代码可以看出，对于 Struts2 来说，如果一个文件域名为 xxx，那么对应的 action 需要使用三个属性来封装文件域的信息。
   - 类型为 File 的 xxx 属性封装了该文件域对应的文件内容；
   - 类型为 String 的 xxxFileName 属性封装了该文件域对应的文件的文件名；
   - 类型为 String 的 xxxContentType 属性封装了该文件域对应的文件的文件类型。
     
   ![img](https://oss.javasec.org/images/1625284296529.png)
     这些属性处理完将会以 File 对象存放在 ActionContext 中的 parameters 中。

8. 拦截器处理完之后将会继续处理流程，调用 action 处理相关的信息等。


而这个漏洞产生的点就在于第 4 步至第 6 步，在第 4 步中，处理一个上传请求中可能出现一些异常及错误信息，这些信息的 message 在经过拼接处理后处理成 LocalizedMessage 对象，并存放在 AbstractMultiPartRequest 对象的 errors 中，此时它是一个 List 对象，在 MultiPartRequestWrapper 处理时将其取出存放在自己的 errors 中，此时它是一个 Collection 对象。

在第 6 步中，拦截器使用了 `LocalizedTextUtil#findText()` 方法，使用全局 valueStack，继续调用 `getDefaultMessage()` 方法，最后调用 `TextParseUtil.translateVariables()` 我们的老朋友触发漏洞。

![img](https://oss.javasec.org/images/1625284296531.png)

描述到这里基本就明白了这个漏洞的产生过程了，我们需要让程序在解析 multipart 上传包时出错，并且在错误信息中（e.getMessage）包含我们可控的部分，这部分内容将会在解析时存储在 errors 中，直到 FileUploadInterceptor 拦截器处理它，调用 `TextParseUtil.translateVariables()`  以 OGNL 解析这其中的内容。

如何产生错误呢？又如何能让错误信息可控呢？在 `JakartaMultiPartRequest#parse()` 方法调用的  `processUpload()` 方法中，会调用 `parseRequest()` 方法，继续调用 `FileUploadBase#parseRequest()` 方法，通过 `getItemIterator()` 创建一个内部类 FileItemIteratorImpl 的对象，这个对象会通过 multipart 请求中的 boundary 来解析一次请求中的相关内容，并创建相关属性。

在 FileItemIteratorImpl 对象的构造方法中，首先对 contentType 进行了判断，要求 contentType 字符以 “multipart/” 开头：

![img](https://oss.javasec.org/images/1625284296533.png)

如果不是将会抛出 InvalidContentTypeException 异常，并将用户的 contentType 拼接了进去：

![img](https://oss.javasec.org/images/1625284296536.png)

这个判断就给了我们触发异常的点，在 `Dispatcher#wrapRequest` 方法中，当 contentType 包含 “multipart/form-data” 字符时，就会认为其是 multipart 请求，但是在实际解析 multipart 请求中的文件对象时，却再次进行判断，要求以 “multipart/”  开头，如果不是将抛出异常。

例如，我们构造如下请求，在一次普通的 GET 请求中加入 `Content-Type: aaamultipart/form-data`。

```http
GET /S2-045/index.action HTTP/1.1
Host: 127.0.0.1:8080
Content-Length: 0
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36
Content-Type: aaamultipart/form-data
Connection: close
```

在 Struts2 的预处理过程中将会将其处理成 MultiPartRequestWrapper，但是在 FileUploadInterceptor 拦截器进行相关 File 对象的解析时将会因为 Content-Type 的不正确抛出异常：

![img](https://oss.javasec.org/images/1625284296537.png)

因此，这次请求将会导致访问不到存在的 index.action，而是由于找不到具有文件上传相应属性的 action 而报出 404 错误。

![img](https://oss.javasec.org/images/1625284296539.png)

这就是 S2-045 的漏洞利用点，在 Content-Type 植入恶意 OGNL 代码即可导致 RCE 漏洞，因此 payload 为：

```
Content-Type: -multipart/form-data-%{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime().exec('open -a Calculator.app')}
```
这个 payload 的构造很简单，只需要在 Content-Type 中包含字符串 “multipart/form-data”，但不以 “multipart/” 开头，在其他位置写 ognl 表达式即可，当然是使用 % 或者 $ 都可以。

但是这里有几个需要注意的点。

第一，在 2.3.29 版本之后，在 `OgnlContext` 的 `get()/put()` 方法中移除了对 `_memberAccess` 关键字符串的支持，也就是说我们将再也不能使用 `#_memberAccess` 来访问 ValueStack 中的 SecurityMemberAccess 对象了。

![img](https://oss.javasec.org/images/1625284296541.png)

于此同时，又在 excludedClasses 中添加 ognl.MemberAccess 和 ognl.DefaultMemberAccess 类，禁止我们调用这两个类中的方法。

![img](https://oss.javasec.org/images/1625284296544.png)

此举旨在防御攻击者篡改 ValueStack 中 SecurityMemberAccess 的参数属性。这样有没有绕过的方式呢？依然是有的，我们看到网上的 S2-045 payload 其实就进行了绕过。

我们再来看一下请求流程，在一次请求到达 Struts2 后：

1. 由 `StrutsPrepareFilter#doFilter` 方法处理，使用 `this.prepare.createActionContext(request, response)` 创建了本次请求的 ActionContext 对象。

2. 从 dispatcher 中获取 Container 使用 getInstance 获取 ValueStackFactory，并使用 createValueStack 创建 OgnlValueStack 对象，使用 container 进行对象的注入，并将 container 放入 context 中。
   
![img](https://oss.javasec.org/images/1625284296546.png)

3. 创建 OgnlValueStack 对象时，使用其构造方法，将会调用 setRoot 方法初始化它的各种属性，如 root、securityMemberAccess、context 等，在初始化 context 对象时，将调用 `Ognl.createDefaultContext()` 方法，然后将 OgnlValueStack 中的一些对象放在 context 中，这其中就包括了 securityMemberAccess。调用 `OgnlContext#setMemberAccess` 将 OgnlValueStack.securityMemberAccess 设置到 OgnlContext._memberAccess 中。
  
![img](https://oss.javasec.org/images/1625284296548.png)

4. 注入时调用 `OgnlValueStack#setOgnlUtil` 方法，将 ognlUtil 中的 excludedClasses、excludedPackageNamePatterns、excludedPackageNames 设置给了 ValueStack 中的 securityMemberAccess 属性，这里我们可以看到，直接使用了 “=” 赋值，是引用对象的方式。
   
![img](https://oss.javasec.org/images/1625284296551.png)

在明白了上述逻辑之后，绕过的方式就变得清晰了，我们想改 OgnlValueStack.securityMemberAccess，可以改 OgnlContext._memberAccess，想改 securityMemberAccess 里面的 excludedClasses 等属性，可以改 OgnlUtil 里面的 excludedClasses 等属性。

这种思路总结出来就是：想改一个类中的属性，但是这个类中没有对应的方法，或者权限不满足条件，就可以
试图修改有同一个引用对象，但是有相关方法和权限的的类。

妙啊妙啊，又学一招。

第二，OgnlUtil 添加了一个新属性 enableEvalExpression 和新方法 checkEnableEvalExpression，在调用 `setValue()` 时不允许一些调用方式。

![img](https://oss.javasec.org/images/1625284296553.png)

到底什么形式是 EvalExpression 呢？

![img](https://oss.javasec.org/images/1625284296555.png)

说白了，在解析表达式的过程中我们的节点不能是 ASTSequence 或 ASTEval。ASTEval 的表现形式是 `(one)(two)`，ASTSequence 的表现形式是 `one,two`。在构造恶意 ognl 表达式时，我们应该避开这两种形式。

所以 payload 的形式需要改为 `(one).(two)` 形式，这种形式是 ASTChain，理论上是永远不会被禁的，因为 Struts2 内部自己有很多这种形式的解析调用。

第三，在 2.5 版本之后，在 `SecurityMemberAccess#isClassExcluded` 方法添加新的判断，通过这个判断，在调用方法时将要求 allowStaticMethodAccess 必须为 true 才能调用，也就是说，我们不再能使用 `new ProcessBuilder()` 这种构造方法的调用来绕过 allowStaticMethodAccess 为 false 时的判断了。

![img](https://oss.javasec.org/images/1625284296556.png)

综上所述，在一些较高的版本中，除了满足触发点的需求外，还需要针对上述三个问题来构造能够绕过的 payload，思路总结起来是这样的：
1. 通过 context 对象的 setMemberAccess 方法将 OgnlValueStack 中的 SecurityMemberAccess 设置为 `@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS`。
2. 但是调用 context 对象的 setMemberAccess 方法时，会被 SecurityMemberAccess 中 `this.excludedPackageNames` 中的 ognl 前缀和 `this.excludedClasses` 中的 ognl.OgnlContext 黑名单给拦掉，所以我们需要先将这两个属性清空。
3. 想要清空 SecurityMemberAccess 中的这些属性，只需要清空 OgnlUtil 中的这些属性即可，Struts2 通过 Container 来控制管理和注入这些 Bean，而 Container 在初始化 OgnlValueStack 和 OgnlContext 中被存在 context 中，可以通过 ` com.opensymphony.xwork2.ActionContext.container` 获得。
4. 获得 Container 对象后，使用 `getInstance()` 方法传入对应类的 class 类型以获取单例对象，并修改其中对应的值。

因此最终的 payload 为：

```
Content-Type: -multipart/form-data-%{(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.excludedClasses.clear()).(#ognlUtil.excludedPackageNames.clear()).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('open -a Calculator.app'))}
```

这里需要注意的是，在清空 OgnlUtil 中的属性之后，由于 Struts2 使用单例模式，再次创建 context 和 ValueStack 时，引用的 OgnlUtil 中的 excludedClasses 等属性依旧为空，因此将无需再次清除。

最后再补充一点，之前我们清空 set 使用的都是赋值的方式 `@java.util.Collections@EMPTY_SET`，在这个 payload 中我们使用的 `clear()` 方法，是因为 ognlUtil 里属性的 set 方法并不是接收 Set 对象直接赋值，而是接收字符串，Class.forName 之后使用 add 放入 set 里，所以我们需要变换一下形式。

![img](https://oss.javasec.org/images/1625284296559.png)

通过以上的分析，不得不说， S2-045 真的是神洞。

# S2-046

与 S2-045 相同的漏洞点，触发位置不同。

> 影响版本：Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-046
> 描述：基于 Jakarta Multipart 解析器执行文件上传时可能导致 RCE。

S2-046 与 S2-045 漏洞点相同，都是由于 Multipart 处理上传请求时出现错误信息，带着用户输入进行了解析导致漏洞。所以我们重点关注，如何还能触发异常报错信息，用户输入又是如何带入到错误信息中的。

在 S2-046 中，报出了两种触发方式，第一种方式是由于 filename 异常引起的。JakartaMultiPartRequest 调用 processUpload 处理上传请求，在 `processFileField()` 方法处理上传文件的字段。

![img](https://oss.javasec.org/images/1625284296561.png)

其中会调用 FileItem 的 getName 方法来获取文件名，实际上是实现类 DiskFileItem 的 getName 方法，调用 `Streams.checkFileName()` 方法。

在 `Streams.checkFileName()` 方法中对文件名进行校验，判断规则中 filename 中不能存在 `\u0000`，否则将会抛出异常，异常信息中放入了 filename。

![img](https://oss.javasec.org/images/1625284296563.png)

这就是漏洞触发点。只需要在 filename 字段中写入恶意 OGNL 表达式，并在不影响 payload 的位置插入"\u0000" 即可，payload 相同，不再重复。

除此之外还有一种情况，在 `struts.multipart.parser` 设置为 jakarta-stream 时，处理 multipart 请求的将会由 AbstractMultiPartRequest 的另一个实现类 JakartaStreamMultiPartRequest 来完成。

这个类同样是调用 `processUpload()` 进行处理，首先使用 `isRequestSizePermitted()` 方法判断当前请求大小是否在允许范围内，如果不是，将会调用 `addFileSkippedError()` 方法，终止接下来的流程。

![img](https://oss.javasec.org/images/1625284296566.png)

`isRequestSizePermitted()`  方法从 request 方法中获得 Content-Length 的值，并和 this.maxSize 进行对比，如果 Content-Length 过大，将会返回 false。

![img](https://oss.javasec.org/images/1625284296571.png)

this.maxSize 是在配置文件中默认配置的值，大小为 2097152，也就是 2G。

![img](https://oss.javasec.org/images/1625284296573.png)

而 `addFileSkippedError()` 方法将 filename 放入了 FileSizeLimitExceededException 异常信息中，并存入了 this.errors 中，将会触发漏洞逻辑。

![img](https://oss.javasec.org/images/1625284296575.png)

因此此漏洞的触发只要将 Content-Length 设置超出最大值，并在 filename 处写入恶意表达式即可，payload 相同，不再重复。


# S2-048

实际上应该是有人发现 `LocalizedTextUtil.findText()` 可以触发漏洞后扫了一遍包，又找到了这个利用点。

> 影响版本：Struts 2.3.x with Struts 1 plugin and Struts 1 action
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-048
> 描述：Apache Struts 2.3.x 系列版本中 struts2-struts1-plugin 存在远程代码执行漏洞。

Struts 2.3.x 版本中，提供了一个 jar 包插件 struts2-struts1-plugin，用来使 struts2 可以兼容 struts1 的 Action。

`org.apache.struts2.s1.Struts1Action` 类为一个 Wrapper 类，用于将 Struts1 时代的 Action 包装成为 Struts2 中的 Action，以让它们在 struts2 框架中继续工作。

![img](https://oss.javasec.org/images/1625284296577.png)

在 Struts1Action 的 execute 方法中，会调用对应的 Struts1 Action 的 execute 方法。在调用完后，会检查 request 中是否设置了 ActionMessage，如果是，则将会对 action messages 进行处理并回显给客户端。处理时使用了 getText 方法，这里就是漏洞的触发点。

所以漏洞的触发条件是：在 struts1 action 中，将来自客户端的参数值设置到了 action message 中。

在官方提供的 Showcase 中，就存在漏洞，在 xml 中为 `org.apache.struts2.showcase.integration.SaveGangsterAction` 设置了 class 为 `org.apache.struts2.s1.Struts1Action`。

![img](https://oss.javasec.org/images/1625284296580.png)

SaveGangsterAction 将 form 表单中的 name 放在了 ActionMessage 中并使用 addMessages 方法放在了 request 里。

![img](https://oss.javasec.org/images/1625284296584.png)

Action messages 会通过 getText 方法进入  `LocalizedTextUtil.findText()` 方法，最终调用 `getDefaultMessage()`，调用 `TextParseUtil.translateVariables()`，后面的漏洞触发逻辑与 S2-045、S2-046 相同。payload 也相同，不再重复。


# S2-052

Xstream 反序列化，没什么好说的。

> 影响版本：Struts 2.1.6 - Struts 2.3.33, Struts 2.5 - Struts 2.5.12
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-052
> 描述：Struts2 REST 插件的 XStream 组件存在反序列化漏洞，可导致 RCE。

Struts2 REST 插件在 `struts-plugin.xml` 中注册了一个 Interceptor：`"org.apache.struts2.rest.ContentTypeInterceptor`，这个拦截器见名知义，用来处理不同的 Content-Type 请求到达时的后续处理流程。

![img](https://oss.javasec.org/images/1625284296587.png)

拦截器调用 ContentTypeHandlerManager 的 getHandlerForRequest 方法，根据不同的 Content-Type 返回不同的 ContentTypeHandler 实现类，这里通过逻辑可以看到，如果 Content-Type 为空或者没有找到响应的文档类型，将使用访问文件后缀来区分本次访问的文档类型。

![img](https://oss.javasec.org/images/1625284296589.png)

ContentTypeHandler 根据不同的文档类型有多个实现类，这里我们重点关注的是其中的 XStreamHandler。

![img](https://oss.javasec.org/images/1625284296592.png)

在 ContentTypeInterceptor 的 getHandlerForRequest 方法获取了对应的 ContentTypeHandler 之后，将会判断 request.getContentLength 是否大于 0 ，如果是将会调用 `handler.toObject(reader, target)` 去处理 `request.getInputStream()` 中的内容。

![img](https://oss.javasec.org/images/1625284296594.png)

可以看到 XStreamHandler 的 toObject 方法使用 `new XStream();` 创建了 XStream 对象，并调用  `fromXML()` 对 `request.getInputStream()` 进行解析，中间没有进行任何的过滤手段。

其中 Content-Type 与 文件后缀对应 handler 的关系如下两图。

![img](https://oss.javasec.org/images/1625284296596.png)

![img](https://oss.javasec.org/images/1625284296599.png)

我们这里使用 struts2-rest-plugin-2.5.12 版本进行测试，依赖的 XStream 版本为 1.4.8 。根据上述描述，我们只需要使用 Content-Type 为 xml 格式发送 payload，或者输入一个不存在的 Content-Type ，访问扩展名为 xml 即可。payload 使用 XStream 反序列化的任意 payload 均可，我这里使用的是 CVE_2017_7957 的 payload。

![img](https://oss.javasec.org/images/1625284296600.png)

当然之前说的 xml 后缀也可。

![img](https://oss.javasec.org/images/1625284296605.png)

# S2-053

在服务端将用户可控的参数放到了 Freemarker 的标签属性中的时候，就会造成RCE。

> 影响版本：Struts 2.0.0 - 2.3.33，Struts 2.5 - Struts 2.5.10.1
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-053
> 描述：Struts2 在使用 Freemarker 模板引擎时，可能由于二次解析导致 RCE。

我们先来创建一个漏洞环境，在 struts.xml 为 Action 的 result 设置为 freemarker，指定一个模板文件。
```
<struts>
    <package name="default" namespace="/" extends="struts-default">
        <action name="hello" class="com.su18.struts.action.HelloWorld">
            <result type="freemarker" name="success">hello.ftl</result>
        </action>
    </package>
</struts>
```
为 Action 添加一个 redirectUri 属性

![img](https://oss.javasec.org/images/1625284296609.png)

在 hello.ftl 模板文件中写入官方通告中受影响的方式。

![img](https://oss.javasec.org/images/1625284296610.png)

访问一下这个参数，可以看到确实是进行了解析。

![img](https://oss.javasec.org/images/1625284296612.png)

那么究竟是如何触发的呢？通过触发点看来，应该是在 Freemarker 处理最后的返回结果时导致的，这有点像 S2-001 ，又有点像 S2-013。

在 S2-001 中我们已经分析过，用户 Action 逻辑走完后，会调用 DefaultActionInvocation 的 `executeResult()`  方法，调用 Result 实现类里的 `execute()` 方法开始处理这次请求的结果。

对于 Freemarker 来说，这个实现类是 FreemarkerResult 方法，将会执行他的 doExecute 方法处理最终的返回结果信息。

首先获取模版的绝对路径,再通过 this.configuration.getTemplate 获取模版的信息.然后调用`template.process(model, writer)` 开始解析模版。

![img](https://oss.javasec.org/images/1625284296614.png)

使用 createProcessingEnvironment 方法创建解析环境 Environment ，并调用其 `process()` 方法解析。

![img](https://oss.javasec.org/images/1625284296617.png)

这个方法就是将 Template 里面的每个元素解析成 TemplateElement 不同的元素，并调用不同元素的 accept 方法再去解析元素内部的内容。

![img](https://oss.javasec.org/images/1625284296619.png)

这部分其实跟 OGNL 的解析过程类似，其实做解析的基本上都是这样，TemplateElement 有多个子类，这些子类根据各自的情况实现了不同的 accept 方法。

![img](https://oss.javasec.org/images/1625284296622.png)

这个漏洞的触发点就是其中的子类 UnifiedCall ，它的 accept 方法解析标签中的 name 等参数，并调用 Environment 的 visitAndTransform 方法处理。

![img](https://oss.javasec.org/images/1625284296625.png)

在这个方法中会调用 TransformControl 的 `onStart()` 方法和 `afterBody()` 方法来处理最终内容，这部分与 S2-013 就非常像。

![img](https://oss.javasec.org/images/1625284296628.png)

`afterBody()` 方法调用对应组件 Bean 的 `end()` 方法，例如 UIBean 将会调用 `evaluateParams()` 方法，调用 `findString()` 方法，继续调用 `findValue()` 方法，最终调用 `TextParseUtil.translateVariables()` 触发漏洞。

![img](https://oss.javasec.org/images/1625284296629.png)

payload 与 S2-045 一致，不再重复。

![img](https://oss.javasec.org/images/1625284296631.png)

# S2-055

XStream 都报了，Jackson 肯定也报啊。

> 影响版本：Struts 2.5 - Struts 2.5.14
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-055
> 描述：由于使用了较低版本的 Jackson 导致的安全漏洞。

在 S2-052 中，我们分析了在 Struts2 REST 插件中由于没有安全的使用 Xstream 组件导致了反序列化漏洞的情况。

在当时其实就可以发现，除了 xml 格式的支持，Struts2 REST 插件还默认支持了 json 格式的数据。可以使用Jackson 插件来解析 json。但是在默认的配置中，对于 Json 的解析使用的是 JsonLibHandler。

![img](https://oss.javasec.org/images/1625284296635.png)

如果我们想要使用 Jackson 来进行解析，那么需要在 struts.xml 文件中进行如下配置：

```
<bean type="org.apache.struts2.rest.handler.ContentTypeHandler" name="jackson" class="org.apache.struts2.rest.handler.JacksonLibHandler"/>
<constant name="struts.rest.handlerOverride.json" value="jackson"/>
```

指定了之后，就会指定 JacksonLibHandler 来处理 json 格式数据，我们看一下他的 toObject 方法：

![img](https://oss.javasec.org/images/1625284296638.png)

可以看到使用 ObjectMapper 获取 ObjectReader 对象，并直接调用 readValue 方法读取输入流中的内容。

Jackson 触发反序列化漏洞需要配置多态，也就是 fastjson 中的 autoType ，这个配置默认是不开启的，因此这个漏洞在利用上还是有一定的局限性。有几种方式配置多态，常见的有以下两种：
1. 全局 Default Typing 机制：`objectMapper.enableDefaultTyping(); `
2. 为相应的 class 添加 @JsonTypeInfo 注解：`@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.WRAPPER_ARRAY)`

这个漏洞由于不是 Struts2 自己的漏洞，这里就不花过多的篇幅进行赘述了。

这里还是使用 struts2-rest-plugin-2.5.12 版本进行测试，依赖的 jackson-databind 版本为 2.6.1 。gadget 我们就用经典的 TemplatesImpl 弹出计算器：

![img](https://oss.javasec.org/images/1625284296639.png)





