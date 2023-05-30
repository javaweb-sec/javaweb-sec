# 前言

本文针对 Struts2 历史版本的 RCE 进行研究和记录。由于漏洞较多，调试过程写的也比较细致，因此篇幅较长，将分为多篇文章进行发布，本文是第一篇，前置信息介绍以及 S2-001/S2-003/S2-005/S2-007/S2-008/S2-009 的漏洞调试。

# 一、简介

Apache Struts2 是一个非常优秀的 JavaWeb MVC 框架，2007年2月第一个 full release 版本发布，直到今天，Struts 发布至  2.5.26 版本，而在这些版本中，安全更新已经更新至 S2-061，其中包含了非常多的 RCE 漏洞修复。

本文将记录 Struts2 全版本的高危漏洞利用和攻防过程，也会保持更新。

# 二、使用

## struts2 配置及使用

Struts2 是一个基于 MVC 设计模式的Web应用框架，它的本质就相当于一个 servlet，在 MVC 设计模式中，Struts2 作为控制器（Controller）来建立模型与视图的数据交互。Struts2 是在 Struts 和WebWork 的技术的基础上进行合并的全新的框架。Struts2 以 WebWork 为核心，采用拦截器的机制来处理的请求。这样的设计使得业务逻辑控制器能够与 ServletAPI 完全脱离开。

对于一次请求，Struts2 的执行流程如下：
1. Filter：首先经过核心的过滤器，也就是通常在 `web.xml` 中配置的 filter 及 filter-mapping，这部分通常会配置 `/*` 全部的路由交给 struts2 来处理。
![img](https://oss.javasec.org/images/1625284287149.png)

2. Interceptor-stack：执行拦截器，应用程序通常会在拦截器中实现一部分功能。也包括在 struts-core 包中 `struts-default.xml` 文件配置的默认的一些拦截器。

 ![img](https://oss.javasec.org/images/1625284293214.png)

3. Action：根据访问路径，找到处理这个请求对应的 Action 控制类，通常配置在 `struts.xml` 中的 package 中。
  
![img](https://oss.javasec.org/images/1625284296350.png)

4. Result：最后由 Action 控制类执行请求的处理，执行结果可能是视图文件，可能是去访问另一个 Action，结果通过 HTTPServletResponse 响应。

实现一个 Action 控制类一共有 3 种方式：
- Action 写为一个 POJO 类，并且包含 excute() 方法。
- Action 类实现 `Action` 接口。
- Action 类继承 `ActionSupport` 类。

对上述流程有所了解后，我们就可以使用 struts2 搭建一个 web 应用了，框架的实现原理和技术细节将在下面漏洞分析时讨论，此处将不再提及。


## struts2 执行流程图

![img](https://oss.javasec.org/images/1625284296353.png)


## OGNL 表达式

Struts2 中支持以下几种表达式语言：OGNL、JSTL、Groovy、Velocity。Struts 框架使用 OGNL 作为默认的表达式语言。

[OGNL](http://commons.apache.org/proper/commons-ognl/) 是 Object Graphic Navigation Language (对象图导航语言)的缩写，是一个开源项目。它是一种功能强大的表达式语言，通过它简单一致的表达式语法，可以存取对象的任意属性，调用对象的方法。

**OGNL 的使用**

表达式的使用非常简单，以下两行代码即可，其中“表达式”为我们编写的 OGNL 表达式，从后两个参数中获取值，“上下文”指的是 OGNL Context，“根”是 ognl 的 Root，可以为 JavaBean、List、Map、.... 等等很多值。

```Java
Object expression = Ognl.parseExpression("表达式");
Object result     = Ognl.getValue(expression,上下文,根);
```
其中需要注意的是，OGNL 表达式的取值范围只能在其 context 和 root 中。

**OGNL Context**

OGNL 上下文对象位于 `ognl.OgnlContext`，上下文实际上是就一个 Map 对象，可以由我们自己创建，通过 `put()` 方法在上下文环境中放元素。

![img](https://oss.javasec.org/images/1625284296355.png)

在这个上下文环境中，有两种对象：根对象和普通对象。可以使用 `setRoot()` 方法设置根对象。根对象只能有一个，而普通对象则可以有多个。即：OgnlContext = 根对象(1个)+非根对象(n个)。

非根对象要通过 `#key` 访问，根对象可以省略 `#key`。获取根对象的属性值，可以直接使用属性名作为表达式，也可以使用 `#Class.field` 的方式；而获取普通对象的属性值，则必须使用后面的方式。

OGNL 主要有以下几种常见的使用：
- 对于类属性的引用：`Class.field`
- 方法调用： `Class.method()`
- 静态方法/变量调用：`@org.su18.struts.Test@test('aaa')` 或 `@org.su18.struts.Constants@MY_CONSTANTS`
- 创建 java 实例对象：完整类路径：`new java.util.ArrayList()`
- 创建一个初始化 List：`{'a', 'b', 'c', 'd'}`
- 创建一个 Map：`#@java.util.TreeMap@{'a':'aa', 'b':'bb', 'c':'cc', 'd':'dd'}`
- 访问数组/集合中的元素：`#Arrays[0]`
- 访问 Map 中的元素：`#Map['key']`
- OGNL 针对集合提供了一些伪属性（如size，isEmpty），让我们可以通过属性的方式来调用方法。

除了以上基础操作之外，OGNL 还支持投影、过滤：
- 投影（把集合中所有对象的某个属性抽出来，单独构成一个新的集合对象）：`collection.{expression}`
- 过滤（将满足条件的对象，构成一个新的集合返回）：`collection.{?|^|$ expression}`

其中上面 `?|^|$` 的含义如下：
- `?`：获得所有符合逻辑的元素。
- `^`：获得符合逻辑的第一个元素。
- `$`：获得符合逻辑的最后一个元素。

在使用过滤操作时，通常会使用 `#this`，这个表达式用于代表当前正在迭代的集合中的对象。

OGNL 还支持 Lambda 表达式：`:[ ... ]`，例如计算阶乘 `#f = :[#this==1?1:#this*#f(#this-1)] , #f(4)`。

还有使用数学运算符，使用“,”号连接表达式，in 与 not in 运算符，比较简单，不再赘述。


## OGNL in Struts2

前面提到过，Struts 框架使用 OGNL 作为默认的表达式语言，那究竟 Struts2 是怎么操作 OGNL 的呢？重点关注的就是 OGNL 解析表达式中关键的三要素 expression、root、Context。

在 Struts2 中，OGNL 上下文即为 ActionContext ，而实际上存放内容是其中的 context，ActionContext 中的 `get()/put()` 方法实际上都在操作 ActionContext 中的 context。

![img](https://oss.javasec.org/images/1625284296356.png)

ActionContext 是 action 的上下文，也可以叫做 action 的数据中心，本质是一个 map，所有数据都存放在这里。

![img](https://oss.javasec.org/images/1625284296359.png)

这里面存了一些属性，我们先来了解一下：

| key                                                          | 存放内容                                                     |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `com.opensymphony.xwork2.ActionContext.locale`               | `LOCALE` 常量                                                |
| `struts.actionMapping`                                       | `ActionMapping` 引用对象，其中包括name/namespace/method/params/result |
| `com.opensymphony.xwork2.util.ValueStack.ValueStack`         | `ValueStack` 引用对象                                        |
| `attr`                                                       | 按照 request > session > application 顺序访问 `attribute`    |
| `application`<br>`com.opensymphony.xwork2.ActionContext.application` | 当前应用 `ServletContext` 中的`attribute`                    |
| `request`                                                    | `HttpServletRequest`中的`attribute`                          |
| `com.opensymphony.xwork2.dispatcher.HttpServletRequest`      | `request` 引用对象                                           |
| `com.opensymphony.xwork2.dispatcher.HttpServletResponse`     | `response` 引用对象                                          |
| `session`<br>`com.opensymphony.xwork2.ActionContext.session` | `HttpSession` 中的`attribute`                                |
| `parameters`<br>`com.opensymphony.xwork2.ActionContext.parameters` | 请求参数 HashMap                                             |
| `com.opensymphony.xwork2.dispatcher.ServletContext`          | `ApplicationContext` 对象                                    |
| `com.opensymphony.xwork2.ActionContext.name`                 | 当前 action 的 name                                          |


OGNL 中的根对象即为 ValueStack（值栈），这个对象贯穿整个 Action 的生命周期（每个 Action 类的对象实例会拥有一个 ValueStack 对象）。当Struts 2接收到一个 `.action` 的请求后，会先建立Action 类的对象实例，但并不会调用 Action 方法，而是先将 Action 类的相应属性放到 ValueStack 的实现类 OgnlValueStack 对象 root 对象的顶层节点（ ValueStack 对象相当于一个栈）。在处理完上述工作后，Struts2 就会调用拦截器链中的拦截器，这些拦截器会根据用户请求参数值去更新 ValueStack 对象顶层节点的相应属性的值，最后会传到 Action 对象，并将 ValueStack 对象中的属性值，赋给 Action 类的相应属性。当调用完所有的拦截器后，才会调用 Action 类的 Action 方法。ValueStack 会在请求开始时被创建，请求结束时消亡。

以上内容作为 Struts2 系列漏洞的基础铺垫，在了解以后可以开始下面的漏洞之旅了。

# 三、漏洞分析

## S2-001

Struts2 对 OGNL 表达式的解析使用了开源组件 `opensymphony.xwork 2.0.3`，所以实际上这是一个 xwork 组件的漏洞，影响了 Struts2。

> 影响版本：WebWork 2.1 (with altSyntax enabled), WebWork 2.2.0 - WebWork 2.2.5, Struts 2.0.0 - Struts 2.0.8
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-001
> 描述：由于在 variable translation 的过程中，使用了 `while(true)` 来进行字符串的处理和表达式的解析，导致攻击者可以在可控的能解析的内容中通过添加 "%{}" 来使应用程序进行二次表达式解析，这就导致了ognl注入，也就是所谓的RCE漏洞。官方将这种解析方式描述为递归，实际上不是传统意义上的递归，只是循环解析。

此漏洞源于 Struts 2 框架中的一个标签处理功能： altSyntax。在开启时，支持对标签中的 OGNL 表达式进行解析并执行。altSyntax 功能在处理标签时，对 OGNL 表达式的解析能力实际上是依赖于开源组件 XWork。

首先来跟一下 Struts2 应用的访问流程，由于我们在 `web.xml` 中指定了由 Struts2 处理的 Filter 为 `org.apache.struts2.dispatcher.FilterDispatcher`，则程序会执行该类的 `doFilter()` 方法进行处理，方法的最后调用 `this.dispatcher.serviceAction()` 方法：
- 通过 `createContextMap()` 方法将获取当前 HttpServletRequest/HttpServletResponse/ServletContext 中的相关信息放到 extraContext 中。
- 通过 ActionProxyFactory 的 `createActionProxy()` 类初始化一个 ActionProxy，在这过程中也会创建 DefaultActionInvocation 的实例，并通过其 `createContextMap()` 方法创建一个 OgnlValueStack 实例，并将 extraContext 全部放入 OgnlValueStack 的 context 中。
- 通过 ObjectFactory 的 `buildAction()`  实际上就是 ClassLoader 的 load 实例化了当前访问的 action 类，并将其放入 OgnlValueStack 的 root 中。

此时，应用程序以及在本次请求中创建了 OgnlValueStack 实例，并将当前请求的各种信息存入了其中的 context 里，然后将当前要访问的 action 实例放入了 root 中。

在 `this.dispatcher.serviceAction()` 方法的最后，执行创建的 ActionProxy 实例的 `execute()` 方法，调用创建的 DefaultActionInvocation 的 `invoke()` 方法，调用程序配置的各个 interceptors 的 `doIntercept()` 方法执行相关逻辑，其中的一个拦截器是 ParametersInterceptor，这个拦截器会在本次请求的上下文中取出访问参数，将参数键值对通过 OgnlValueStack 的 setValue 通过调用 `OgnlUtil.setValue()` 方法，最终调用 `OgnlRuntime.setMethodValue` 方法将参数通过 set 方法写入到 action 中，并存入 context 中。

此时 OgnlValueStack 实例中 root 中的 Action 对象的参数值已经被写入了。

在循环执行 interceptors 结束后，DefaultActionInvocation 的 `invoke()` 方法执行了 `invokeActionOnly()` 方法，这个方法通过反射调用执行了 action 实现类里的 execute 方法，开始处理用户的逻辑信息。

用户逻辑走完后，会调用 DefaultActionInvocation 的 `executeResult()`  方法，调用 Result 实现类里的 `execute()` 方法开始处理这次请求的结果。

如果返回结果是一个 jsp 文件，则会调用 JspServlet 来处理请求，然后交由 Struts 来处理解析相关的标签。

如果在 jsp 中想使用 struts2 的标签，需要在头部声明： `<%@taglib prefix="s" uri="/struts-tags" %>`，对于各个标签的属性及处理类，在 struts2-core 包中的 `struts-tags.tld` 中进行了定义，在对标签进行解析时，会根据不同的 tag 类型找到不同的 `TagSupport` 的实现类进行处理。

在解析一个标签如 `<s:textfield name="username" label="用户名"/>`，在标签的开始和结束位置，会分别调用对应实现类如`org.apache.struts2.views.jsp.ComponentTagSupport` 中的 `doStartTag()` 及 `doEndTag()` 方法：
-  `doStartTag()`：获取一些组件信息和属性赋值，总之是些初始化的工作
-  `doEndTag()`：在标签解析结束后需要做的事，如调用组件的 `end()` 方法

而这个漏洞的触发点，就从 `doEndTag()` 开始，这个方法调用组件 `org.apache.struts2.components.UIBean` 的`end()` 方法，随后调用 `evaluateParams()` 方法，这个方法判断了 altSyntax 是否开启，并调用 `findValue()` 方法寻找参数值：

![img](https://oss.javasec.org/images/1625284296361.png)

`findValue()` 方法调用了 `com.opensymphony.xwork2.util.TextParseUtil#translateVariables` 来解析和处理

![img](https://oss.javasec.org/images/1625284296363.png)

这个方法实际上就是真正的漏洞点，由于篇幅有限，这里不贴代码，用文字来描述一下逻辑：
1. 对要解析的表达式寻找最外层的 `%{}`，至于为什么是 `%{}`，是在之前提到的 `evaluateParams()` 中定义的，并去除掉。
2. 调用 `ValueStack#findValue()` 实际上是实现类 `OgnlValueStack` 的该方法来调用 `OgnlUtils` 解析这个表达式。
3. 解析过后将解析结果替换回原来的表达式中，继续第一步，如果找不到 `%{}`，则通过 break 跳出`while(true)` 循环。

到这一步，整个漏洞的原理就大概说清了，用户通过使用 `%{}` 包裹恶意表达式的方式，将参数传递给应用程序，应用程序由于处理逻辑失误，导致了二次解析，造成了漏洞。

那漏洞究竟是如何触发的呢？其实就在于，第一次 OGNL 解析，解析的是 `%{var}`，解析的实际上是标签里写的变量名，而由于在 Struts 收到对应的 action 请求时，将 Action 对象的相关属性都放在了OgnlValueStack 的 root 对象中，此时由于是根节点的属性， OGNL 可以不使用 “#” 直接使用名称获得，也就获得我们输入的恶意表达式，此时再次进行二次解析，就完成了漏洞的触发。

而触发点，很多文章描述在表单验证失败，其实跟验证没关系，只是在一次请求中， ValueStack 中写入了用户请求参数，也就是对应 action 中的属性，在其消亡前如果被调用并解析，就会触发此漏洞。而在表单验证错误或成功或者任意情况，如果跳转回原来的页面，那在这个请求处理结束前，ValueStack 中的用户参数还依然存在，页面在解析标签时就会使用表达式解析将标签的内容解析出来重新展现在页面上。只是在登陆的位置或者配置了 Validation 的位置由于错误时会返回原来的界面，所以成为了漏洞经常出现的区域。

## S2-003

Struts2 在解析参数时，将所有参数名都使用了 OGNL 来解析，构成了这个漏洞。

> 影响版本：Struts 2.0.0 - Struts 2.1.8.1
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-003
> 描述：在拦截器 ParametersInterceptor 调用 `setParameters()` 装载参数时，会使用`stack.setValue()` 最终调用 `OgnlUtil.setValue()` 方法来使用 OGNL 表达式解析参数名，造成漏洞。

在之前梳理逻辑过程中提到过，程序会调用设置的拦截器栈来执行相关命令，其中一个拦截器是 ParametersInterceptor，这个拦截器会解析参数，将参数放入 OgnlValueStack root 中的 action 中，也同时将参数调用 set 方法写入要执行的 Action 类中。

在拦截器的 `doIntercept()` 方法中，初始化的过程中将 `DENY_METHOD_EXECUTION` 设置为 true。

![img](https://oss.javasec.org/images/1625284296365.png)

然后调用 `setParameters()` 方法，循环参数 Map，首先调用 `this.acceptableName(name)` 来校验参数名是否非法，在较低版本中是判断是否包含 `#,=:`

![img](https://oss.javasec.org/images/1625284296367.png)

在高一点的版本中是使用正则来匹配

![img](https://oss.javasec.org/images/1625284296370.png)

如果校验通过则调用 `stack.setValue(name, value)` 方法，这个方法会将待解析的表达式以 “conversion.property.fullName” 的值放在 context 里，然后调用 `OgnlUtil.setValue()` 方法。

中间有个 `compile()` 方法会先调用 `ognl.Ognl#parseExpression` 方法，这个方法创建了一个 OgnlParser 对象，并调用其 `topLevelExpression()` 方法解析给定的 OGNL 表达式，并返回可由 OGNL 静态方法使用的表达式的树表示形式（Node）。

在 OGNL 中，有一些不同类型的语法树，这些在在解析表达式的过程中，根据表达式的不同将会使用不同的构造树来进行处理，比如如果表达式为 `user.name`，就会生成 ASTChain，因为采用了链式结构来访问 user 对象中的 name 属性。

![img](https://oss.javasec.org/images/1625284296372.png)

这些树都是 SimpleNode 的子类中，且各子类都根据自己的特性需求对父类的部分方法进行了重写，这些特性可能导致表达式最终执行结果受到影响。这些树对应的表现形式以及重写的方法可以参考 [这篇文章](https://xz.aliyun.com/t/111)。

而本次漏洞触发形式就在于 `(one)(two)` 这种表达形式，属于 `ASTEval` 类型。

![img](https://oss.javasec.org/images/1625284296373.png)

看一下解析执行流程：
1. 取第一个节点，也就是 one，调用其 `getValue()` 方法计算其值，放入 expr 中；
2. 取第二个节点，也就是 two，赋值给 source ；
3. 判断 expr 是否为 node 类型，如果不是，则调用 `Ognl.parseExpression()` 尝试进行解析，解析的结果强转为 node 类型；
4. 将 source 放入 root 中，调用 node 的 `setValue()` 方法对其进行解析；
5. 还原之前的 root。

因此我们得知：使用 `(one)(two)` 这种表达式执行时，将会计算 one ，two，并将 two 作为 root 再次为 one 的结果进行计算。如果 one 的结果是一个 AST，OGNL 将简单的执行解释它，否则 OGNL 将这个对象转换为字符串形式然后解析这个字符串。

所以，比如使用 Runtime 弹计算器，原本的表达式可以这样写：
```
@java.lang.Runtime@getRuntime().exec('open -a Calculator.app')
```
但是使用 `(one)(two)` 可以改成这样：
```
('@java.lang.Runtime'+'@getRuntime().exec(\'open -a Calculator.app\')')('aaa')
('@java.lang.Runtime@'+'getRuntime().exec(#aa)')(#aa='open -a Calculator.app')
```
将 one 用字符串括起来，甚至是进行拼接，后面再跟一个括号，这样程序就会对 one 进行二次解析，第一次解析成为字符串，第二次解析成为对应的 AST 并执行，也可以将其中的部分变量拆分到 two 中，因为 two 会作为 one 的 root 解析执行，可以拿到其中的值。

又由于表达式的执行是由右向左执行的，因此向右面写入更多个括号，都会依次拆分，最后执行到 one 表达式中：

```
('@java.lang.Runtime'+'@getRuntime().exec(\'open -a Calculator.app\')')('su18')('su19')('su20')('su21')('su22')('su23')('su24')('su25')('su26')('su27')('su28')('su29')
```
或者向左叠入更多层级的括号：

```
('su23')(('su22')(('su21')(('su20')(('su19')(('@java.lang.Runtime'+'@getRuntime().exec(\'open -a Calculator.app\')')('su18'))))))
```
这些写法都不影响最终 one 表达式的执行，如下图均可以成功弹出计算器：

![img](https://oss.javasec.org/images/1625284296375.png)

以上是使用`Ognl.parseExpression()`  加 `Ognl.getValue()` 来执行的，与 `OgnlUtil.getValue()` 一致。

那使用 `OgnlUtil.setValue()`，调用会一致吗？答案是否定的。

![img](https://oss.javasec.org/images/1625284296377.png)

如上图，我们的 payload 报错了，为什么呢？`OgnlUtil.setValue()` 的调用链为：`OgnlUtil.setValue()`-> `OgnlUtils.compile()` ->`Ognl.setValue()` -> `Node.setValue()` -> `SimpleNode.evaluateSetValueBody()` ->`ASTEval.setValueBody()`。

在 `ASTEval.setValueBody()` 中，分别取了 `children[0]` 的 `children[1]` Node 并调用其 `getValue()` 方法。这个方法的调用链为：`SimpleNode.getValue()` 、`SimpleNode.evaluateGetValueBody()`、 `ASTEval.getValueBody()`，到这步进入了 `OgnlUtil.getValue()` 的漏洞触发链。

也就是说，在使用 `OgnlUtil.setValue()` 执行恶意表达式时，要比 `OgnlUtil.getValue()` 多出一步取节点并执行的步骤，如下图两种方法都可以弹出计算器：

![img](https://oss.javasec.org/images/1625284296383.png)

上面讨论了调用静态方法的表达式，那如果想要修改 context 里的值呢？根据官方文档的描述和测试的结果，以下的方式都可以：

```
('#context[\'key\']=aaaa')('su18')
('#context[\'key\']')('su18')=aaa
('#context[\'key\']=#a')(#a='aaa')
```

还有关键的一点是：在对表达式进行解析时，由于在 `OgnlParserTokenManager` 方法中使用了 `ognl.JavaCharStream#readChar()` 方法，在读到 `\\u` 的情况下，会继续读入 4 个字符，并将它们转换为 char，因此 OGNL 表达式实际上支持了 unicode 编码，这就绕过了之前正则或者字符串判断的限制。

![img](https://oss.javasec.org/images/1625284296384.png)

在解析完表达式执行方法的时候，会调用 `MethodAccessor#callMethod/callStaticMethod` 方法，在调用之前会在 context 中取 `xwork.MethodAccessor.denyMethodExecution` 的值转为布尔型进行判断，如果是 true 则不会调用方法，只有为 false 才会进行调用。

![img](https://oss.javasec.org/images/1625284296384.png)

因此，这个漏洞的触发流程就明确了，攻击者在参数名处传入恶意表达式：
- 使用 unicode 编码特殊字符绕过对关键字符黑名单的判断；
- 将 context 中的 `xwork.MethodAccessor.denyMethodExecution` 值修改为 false，这样在后面才可以调用方法；
- 执行恶意的表达式。

因此 S2-003 的漏洞利用 payload 为：

```
(su18)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003d\u0023su19')(\u0023su19\u003dnew\u0020java.lang.Boolean(false)))&(su20)(('\u0023su21.exec(\'open -a Calculator.app\')')(\u0023su21\u003d@java.lang.Runtime@getRuntime()))
```
或者
```
(%27\u0023context[\%27xwork.MethodAccessor.denyMethodExecution\%27]\u003dfalse%27)(su18)(su19)&(%27\u0023su20\u003d@java.lang.Runtime@getRuntime().exec(\%27open%20-a%20Calculator.app\%27)%27)(su21)(su22)
```

当然也可以根据上面的分析随意改成自己喜欢的样子。这里有一点要注意的是，可以看到第二个 payload 没有直接使用 @ 调用静态方法的方式，而是使用了 `#su=` 进行了赋值，这是因为在 OGNL 对参数解析时，静态方法的解析会排在其他方式的前面，这就导致了还没修改 context 里的值，导致无法执行，所以先进行了赋值。主要的原因是 `TreeMap` 的默认排序是按照 key 的字典顺序排序即升序。

![img](https://oss.javasec.org/images/1625284296387.png)


## S2-005

官方在 struts2-core 2.0.12 对 S2-003 进行了修复，实际上是 xwork 2.0.6 版本修复。S2-005 是对 S2-003 修复的绕过。

> 影响版本：Struts 2.0.0 - Struts 2.1.8.1
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-005
> 描述：为了修复 S2-003，官方添加了 SecurityMemberAccess ，但是没有从根本上进行修复漏洞。

先来 diff 一下更新，在 `ParametersInterceptor#setParameters` 方法，使用了 ValueStackFactory 为当前值栈重新初始化 ValueStack，不再使用原有的 ValueStack，并为其设置了相关属性，包括新增的 `acceptParams` 和 `excludeParams` 是接收访问的参数名白名单和黑名单。

![img](https://oss.javasec.org/images/1625284296389.png)

新增了 MemberAccessValueStack 和 ClearableValueStack 接口，由 OgnlValueStack 实现，用来配置额外的属性和清除 context 中的内容，并为 OgnlValueStack 添加了新的 allowStaticMethodAccess 和 securityMemberAccess 属性，用来限制静态方法的调用。

![img](https://oss.javasec.org/images/1625284296393.png)

在为 ValueStack 设置 root 时，会创建 `SecurityMemberAccess` 对象，并调用 `Ognl.createDefaultContext()` 方法将其放在 Context 里，key 为 `OgnlContext.MEMBER_ACCESS_CONTEXT_KEY`，也就是 `_memberAccess`。

![img](https://oss.javasec.org/images/1625284296395.png)

在 OGNL 解析完表达式，试图调用方法时，会调用 MemberAccess 的 `isAccessible()` 方法来判断是否允许调用，xwork 创建了 `SecurityMemberAccess` 对象继承自 DefaultMemberAccess 并重写了这个方法，因此，我们需要让这个方法返回 true，才能执行最终的方法。

我们先使用 S2-003 的 payload 再打一次，看一下调用流程：

首先在`ParametersInterceptor#setParameters` 方法创建新的 ValueStack，里面 securityMemberAccess 的 allowStaticMethodAccess 默认为 true，excludeProperties 里有一个数据，是在配置文件中读出来的参数名的黑名单，acceptProperties 中没有数据。

![img](https://oss.javasec.org/images/1625284296396.png)

在 payload 的第一步设置 denyMethodExecution 为 false 没有问题，第二步调用方法前执行 `isAccessible()` 判断，由于 allowStaticMethodAccess 为 true ，所以 `!getAllowStaticMethodAccess()` 返回false，程序调用父类 DefaultMemberAccess 的 `isAccessible()` 方法判断调用的类是不是 public 属性，由于我们调用的 `Runtime.getRuntime()` 没有问题，所以这步判断也直接过了，接下来程序会调用到 `isAcceptableProperty()` ，会进行两个判断：`isAccepted()` 和 `isExcluded()` ：
- `isAccepted()`：判断参数名是否在白名单中，如果白名单为空，则返回 true；如果白名单不为空，则进行匹配，匹配到了就返回 true，匹配不到就返回 false；
- `isExcluded()` ：判断参数是否在黑名单中，如果匹配到了，则返回 true，如果没匹配到或黑名单为空，则返回 false。

在这种判断下，只有当 `isAccepted()` 返回 true，`isExcluded()` 返回 false 的情况下，才能调用方法，最好的方式是黑白名单都为空，这样直接绕过判断。

由于 `MethodAccessor#callMethod/callStaticMethod` 时传入的 propertyName 为 null，所以进行判断的参数  paramName 为 null，会触发空指针异常，中断调用流程。

![img](https://oss.javasec.org/images/1625284296398.png)

所以我们需要将 excludeProperties 设置为空集，绕开判断，其他不变，与 S2-003 保持一致。最好的 payload 是再将 acceptProperties 设为空集，allowStaticMethodAccess 设置为 true，用来兼容多种情况。因此，最终的 payload 为：
```
(%27\u0023_memberAccess.allowStaticMethodAccess\u003dtrue%27)(su18)(su19)&(%27\u0023_memberAccess.acceptProperties\u003d@java.util.Collections@EMPTY_SET%27)(su20)(su21)&(%27\u0023context[\%27xwork.MethodAccessor.denyMethodExecution\%27]\u003dfalse%27)(su22)(su23)&(%27\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET%27)(su24)(su25)&(%27\u0023su26\u003d@java.lang.Runtime@getRuntime().exec(\%27open\u0020/System/Applications/Calculator.app\%27)%27)(su27)(su28)
```
当然了，这是执行命令的 payload，如果只是想读取/修改 context 中的内容的话就不需要这么麻烦了。

## S2-007

用字符串拼接还不进行处理，yyds。

> 影响版本：Struts 2.0.0 - Struts 2.2.3
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-007
> 描述：关于表单我们可以设置每个字段的规则验证，如果类型转换错误时，在类型转换错误下，拦截器会将用户输入取出插入到当前值栈中，之后会对标签进行二次表达式解析，造成表达式注入。

可以为 field 配置验证规则，这里使用了 S2-007 的靶场进行调试，如下可看到为 age 配置了类型和大小限制：
```xml
<validators>
    <field name="age">
        <field-validator type="int">
            <param name="min">1</param>
            <param name="max">150</param>
        </field-validator>
    </field>
</validators>
```
此时如果输入不正确的数据类型，会校验失败并提示：

![img](https://oss.javasec.org/images/1625284296400.png)

此时程序会进入 struts 拦截器栈中的 `ConversionErrorInterceptor#intercept()` 方法，这个方法从 context 中获取类型转换错误的字段键值对

![img](https://oss.javasec.org/images/1625284296402.png)

拿出这些类型转换错误的键值对，创建了一个新的 HashMap fakie，并将其储存进去，储存之前对参数值进行了处理，调用了 `getOverrideExpr()` 方法在参数值前后加了引号。

![img](https://oss.javasec.org/images/1625284296404.png)

把 fakie 放在了 context 中的 `original.property.override` 中，创建了一个 PreResultListener，在 Action 完成控制处理之后，将 fakie 取出放入 stack 的 overrides 中，在后面 `findValue()` 时，会取出其中的值并解析。

所以这个漏洞的触发点，其实和 S2-001 是一样的，是在 `doEndTag()` 解析时回填用户输入时进行 OGNL 解析触发的，但是取值的方式不同： S2-001 是从 ValueStack 中的 root 对象直接取值，而 S2-007 由于类型验证失败，用户输入值没法放到 Action 对象中，那怎么办呢？

就是上面提到的 overrides，程序将用户输入前后添加单引号处理成字符串，然后放在 context 和 stack 对象中，在  `doEndTag()`  解析对应的参数 `%{age}` 时，会调用 `lookupForOverrides()` 方法在 stack 中取回用户输入。

![img](https://oss.javasec.org/images/1625284296406.png)

然后调用 `getValue()` 方法实际上就是 `Ognl.getValue()` 方法解析字符串。

![img](https://oss.javasec.org/images/1625284296408.png)

因此我们只需要闭合 `getOverrideExpr()` 方法添加的单引号，即可构成 OGNL 注入，由于这个方法使用了字符串拼接的方式，所以最终的 payload 为：
```
' + (#_memberAccess["allowStaticMethodAccess"]=true ,#context["xwork.MethodAccessor.denyMethodExecution"]=new java.lang.Boolean("false"),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('open -a Calculator.app').getInputStream())) + '
```

这个 payload 由于是直接写 OGNL 表达式，不用那么多复杂的变化，所以比较简单。

除了 ConversionErrorInterceptor，还有一个类能触发类型转换错误，那就是 RepopulateConversionErrorFieldValidatorSupport，原理相同，此处略过。

## S2-008

S2-008 还是对 S2-003 的绕过。

> 影响版本：Struts 2.0.0 - Struts 2.3.17
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-008
> 描述：官方文档提出了 4 种绕过防御的手段，其中关注比较多的是 Debug 模式导致的绕过。

通过 S2-003/S2-005 ，Struts 2 为了阻止攻击者在参数中植入恶意 OGNL，设置了 `xwork.MethodAccessor.denyMethodExecution` 以及 `SecurityMemberAccess.allowStaticMethodAccess`，并使用白名单正则 `[a-zA-Z0-9\.][()_']+`  来匹配参数中的恶意调用，但是在一些特殊情况下，这些防御还是可以被绕过。

官方文档描述了四种情况：
1.  Struts <= 2.2.3 ExceptionDelegator RCE：看了一下，指的就是 S2-007。
2.  Struts <= 2.3.1 CookieInterceptor RCE：acceptedParamNames 没有应用到 Cookie 拦截器上，而 cookie 名也同样会被解析。

接下来跟一下 CookieInterceptor 的逻辑：

![img](https://oss.javasec.org/images/1625284296410.png)

从 ServletActionContext 获取当前的 request 对象，并获取当前请求的 Cookie 对象数组，循环这个数组，在里面取得 name 和 value，调用 `populateCookieValueIntoStack()` 方法，顾名思义，将 cookie 值放入值栈中，最终调用 `stack.setValue()` 方法。

![img](https://oss.javasec.org/images/1625284296413.png)

由于 CookieInterceptor 不在默认拦截器栈中，因此需要我们进行配置：

```
<interceptor-ref name="defaultStack" />
<interceptor-ref name="cookie">
        <param name="cookiesName">*</param>
        <param name="cookiesValue">*</param>
</interceptor-ref>
```
而大多 Web 容器对 Cookie 名称都有字符限制，例如 tomcat 不允许出现以下字符:

```java
 public static final char SEPARATORS[] = { '\t', ' ', '\"', '(', ')', ',', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '{', '}' };
```

这基本上阻拦了 ognl 调用的方式，想了一下确实没有想到能绕过的方式。略过。

3. Struts <= 2.3.1 ParameterInterceptor 任意文件覆盖：这是一种思路的拓展，由于 acceptedParamNames 正则允许了括号，因此可以调用一些构造方法可以执行操作的类，比如使用 FileWriter 的构造方法传入文件名可以直接创建这个文件或者清空其内容：
```
name=/tmp/1.txt&su18[new+java.io.FileWriter(name)]=1
```
这里需要注意的是，如果 FileWriter 的参数直接写文件名的话，无法跳出执行目录，因为正则不允许使用 "\" 或者 "/"，所以无法使用相对路径或者绝对路径，但是我们可以使用当前请求 action 的参数，因为这些参数会被放入 ValueStack  的 root 中，无需 # 即可调用。当然这里也可以使用 `(one)(two)` 的方式，与之前一致。

4. Struts <= 2.3.17 DebuggingInterceptor RCE

严格意义上来讲，这并不算是一个漏洞，在应用程序配置成为了 devMode 时，开发人员提供了一个拦截器 DebuggingInterceptor 来进行调试，提供了执行命令等功能，按理来说生产环境上是不应该使用开发模式，但这算一种风险。

在 struts.xml 上进行配置即可开启 devMode :`<constant name="struts.devMode" value="true" />`。

开启之后，会成功进入 `DebuggingInterceptor#intercept` 的相关逻辑，首先取得 request 中的参数 "debug"，这个参数可以有 4 种值，分别对应了 DebuggingInterceptor 提供的四种功能。

![img](https://oss.javasec.org/images/1625284296415.png)

-  `debug=xml` ：从 ServletActionContext 中获取 response 对象，把一些 context 中的内容以 xml 的格式打印出来。

![img](https://oss.javasec.org/images/1625284296419.png)

- `debug=command&expression=`：非常清晰的漏洞调用点，如果参数 debug 是 command ，取参数 expression 的值，并调用 `stack.findValue()` 进行解析。

![img](https://oss.javasec.org/images/1625284296421.png)

- `debug=console`：如果参数 debug 是 console，struts2 调用 freemarker 跳转了 `org/apache/struts2/interceptor/debugging/console.ftl` 的 html 模板。

![img](https://oss.javasec.org/images/1625284296423.png)

模板引入了 struts/webconsole.html ，我们也可以直接访问这个路径来访问这个页面

![img](https://oss.javasec.org/images/1625284296426.png)

![img](https://oss.javasec.org/images/1625284296428.png)

这个页面提供了一个黑色的交互页面，可以输入 ognl 表达式，解析结果会返回在页面上，而这个功能的实现实际上是使用了 `debug=command&expression=` 的功能。

- `debug=browser&object=`：如果参数 debug 是 browser，取参数 object 的值，如果没有默认为 `#context`，并调用 `stack.findValue()` 进行解析，结果也是使用了 freemarker 的 `/org/apache/struts2/interceptor/debugging/browser.ftl` 进行展示。

![img](https://oss.javasec.org/images/1625284296429.png)

由上可知，开启 debug 模式后将会有两个 RCE 的点。

## S2-009

S2-009 是对 S2-005 的绕过，但是不同的是，S2-009 是参数值注入，对于 S2-003/S2-005 都是参数名的 OGNL 注入，这次的漏洞出在参数值上。

> 影响版本：Struts 2.0.0-Struts 2.3.1.1
> 参考链接：https://cwiki.apache.org/confluence/display/WW/S2-009
> 描述：由于 ParametersInterceptor 对参数名进行了过滤，对参数值没有进行过滤，结合其正则可以使用 `()` 和 `[]` 的特性，以及 Struts Action 参数会被放在 ValueStack Root 里可以不使用 # 调用的特性，可以绕过校验。

在 S2-008 的第三种情况中，我使用了在 action 参数中填入路径，用来规避正则校验的方法，但是小了，格局小了，这一特性可以直接用来绕过对参数值的校验。由于在进行 acceptableName 判断时，使用了如下正则对参数名进行判断，而对参数值没有进行判断：

```
private String acceptedParamNames = "[a-zA-Z0-9\\.\\]\\[\\(\\)_'\\s]+";
```

这样就导致了安全漏洞，由于 Struts Action 参数会被直接放在 ValueStack 里，因此可以不使用 # 调用，可以直接构造 payload ：

```
param=(#context["xwork.MethodAccessor.denyMethodExecution"]=new java.lang.Boolean(false), #_memberAccess["allowStaticMethodAccess"]=true,@java.lang.Runtime@getRuntime().exec("open -a Calculator.app"))(su18)&(param)(su20)
```

在有些文章中使用了payload：`one[(two)(three)]`，在 OGNL 解析这个表达式时，他本身是 ASTChain，首先会解析成为两个 ASTProperty ：`one` 和 `[(two)(three)]`，然后分别调用他们的 `ASTProperty#setValue` 方法，经过一系列的调用，最后调用 `getProperty()` 方法获取值，并调用 `OgnlRuntime.getProperty()` 获取对应的属性，对于 `[(two)(three)]` 来说，解析成为 ASTEval 之后的过程与之前分析的无异，会将 three 中内容作为 two 的 root 对象来执行。

![img](https://oss.javasec.org/images/1625284296431.png)

简单来说使用 `one[(two)(three)]` 表达式，会对 two 进行二次解析。

因此构造如下，或者类似 `"su17[('@java.lang.Runtime@getRuntime().exec(#su19)')(#su19='open -a Calculator.app')]"` ，即可弹出计算器。

![img](https://oss.javasec.org/images/1625284296434.png)

除了使用之前熟悉的 ASTEval 的 payload ，官方通报了一种新的表达式执行方式： `top['foo'](0) `，在上下文中，可以用 top 来访问 Action 中的成员变量，这种方式会对 foo 进行二次解析。

这种方式正好对应了我们的思路，使用一个 String 类型的 Action 参数，在值中写入恶意代码，然后通过 top 调用并进行二次解析，造成 OGNL 注入漏洞。

那为什么 top 可以访问呢？来调试研究一下，首先 `top['foo'](0)` 会被解析成 `(top['foo'])(0)` 这个 ASTEval 的形式，并分隔成为两段，其中 `top['foo']` 是 ASTChain 对象。

![img](https://oss.javasec.org/images/1625284296436.png)

这个对象又会被解析成 `top` 和 `['foo']` 两个 ASTProperty 对象，会调用 `OgnlRuntime.getProperty()` 获取其值，取值的方式是调用 PropertyAccessor 的实现类的 `getProperty()` 方法，对于目前的情况下，是 CompoundRootAccessor，在这个实现类中，判断如果名称是 top 的情况下，会返回 root 中的第一个对象。

![img](https://oss.javasec.org/images/1625284296438.png)

而第一个对象就是 Action 对象，里面存放了参数信息，可以直接调用到，所以在这里 payload 也可以为

```
param=(#context["xwork.MethodAccessor.denyMethodExecution"]=new java.lang.Boolean(false), #_memberAccess["allowStaticMethodAccess"]=true,@java.lang.Runtime@getRuntime().exec("open -a Calculator.app"))(su18)&top["param"](0)
```