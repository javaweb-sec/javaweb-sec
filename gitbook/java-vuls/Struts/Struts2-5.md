
# 0x01 前言

Struts2 漏洞调试总结


# 0x02 目录

点击左边连接可以直接跳到对应漏洞的调试记录。

| 链接                                                     | 描述                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [前言](https://su18.org/post/struts2-1/#前言)                | 前言及简介                                                   |
| [使用](https://su18.org/post/struts2-1/#二-使用)             | Struts2/OGNL 的简单使用及配置                                |
| [S2-001](https://su18.org/post/struts2-1/#s2-001)            | OGNL 循环解析导致的 RCE 漏洞                                 |
| [S2-003](https://su18.org/post/struts2-1/#s2-003)            | 对参数名使用 OGNL 解析导致的 RCE 漏洞                        |
| [S2-005](https://su18.org/post/struts2-1/#s2-005)            | S2-003 的绕过                                                |
| [S2-007](https://su18.org/post/struts2-1/#s2-007)            | 验证类型转换错误时，会导致二次表达式解析                     |
| [S2-008](https://su18.org/post/struts2-1/#s2-008)            | S2-003 的绕过                                                |
| [S2-012](https://su18.org/post/struts2-2/#s2-012)            | 重定向的路径中使用了 `%{}` 导致了的 RCE 漏洞                 |
| [S2-013](https://su18.org/post/struts2-2/#s2-013)            | 链接标签带入参数时导致的 OGNL 解析漏洞                       |
| [S2-014](https://su18.org/post/struts2-2/#s2-014)            | S2-013 的绕过                                                |
| [S2-015](https://su18.org/post/struts2-2/#s2-015)            | result 中配置了用户可控的参数时导致了解析漏洞                |
| [S2-016](https://su18.org/post/struts2-2/#s2-016)            | 对重定向前缀解析导致的漏洞                                   |
| [S2-018](https://su18.org/post/struts2-2/#s2-018s2-019)      | 使用 action 前缀绕过访问控制限制                             |
| [S2-019](https://su18.org/post/struts2-2/#s2-018s2-019)      | 关闭了动态方法调用                                           |
| [S2-020](https://su18.org/post/struts2-2/#s2-020s2-021s2-022) | 在请求参数中使用 class.classloader 中的信息形成漏洞利用链    |
| [S2-021](https://su18.org/post/struts2-2/#s2-020s2-021s2-022) | S2-020 的绕过                                                |
| [S2-022](https://su18.org/post/struts2-2/#s2-020s2-021s2-022) | S2-020 在 Cookie 中的利用                                    |
| [S2-026](https://su18.org/post/struts2-2/#s2-026)            | 在参数中，官方对 `top['foo']` 形式的访问进行了拦截           |
| [S2-029](https://su18.org/post/struts2-4/#s2-059)            | 在用户的错误配置下，可能导致 OGNL 解析漏洞，见 S2-059        |
| [S2-032](https://su18.org/post/struts2-2/#s2-032)            | 在 DMI 开启时，使用 method 前缀可以导致任意代码执行漏洞      |
| [S2-033](https://su18.org/post/struts2-2/#s2-033)            | 在使用 REST 插件，并启用动态方法调用时，可导致 RCE           |
| [S2-036](https://su18.org/post/struts2-4/#s2-059)            | 在用户的错误配置下，可能导致 OGNL 解析漏洞，见 S2-059        |
| [S2-037](https://su18.org/post/struts2-2/#s2-037)            | 在使用 REST 插件时，对方法名进行了解析，可导致 RCE           |
| [S2-045](https://su18.org/post/struts2-3/#s2-045)            | 基于 Jakarta Multipart 解析器执行文件上传时可能导致 RCE      |
| [S2-046](https://su18.org/post/struts2-3/#s2-046)            | 与 S2-045 相同的漏洞点，触发位置不同                         |
| [S2-048](https://su18.org/post/struts2-3/#s2-048)            |  struts2-struts1-plugin 存在远程代码执行漏洞 |
| [S2-052](https://su18.org/post/struts2-3/#s2-052)            | Xstream 反序列化                                             |
| [S2-053](https://su18.org/post/struts2-3/#s2-053)            | Struts2 在使用 Freemarker 模板引擎时，可能由于二次解析导致 RCE |
| [S2-055](https://su18.org/post/struts2-3/#s2-055)            | Jackson 反序列化                                             |
| [S2-057](https://su18.org/post/struts2-4/#s2-057)            | namespace 处插入 OGNL 代码引发的漏洞                         |
| [S2-059](https://su18.org/post/struts2-4/#s2-059)            | 不正确的给标签属性添加 OGNL 解析，可能会造成二次解析导致 RCE |
| [S2-061](https://su18.org/post/struts2-4/#s2-061)            | 对 S2-059 沙盒的绕过                                         |

# 0x03 漏洞点

在文章编制过程中，有时是正向跟随漏洞触发逻辑，有时是逆向反推调用，这种情况对很多漏洞细节和触发并没有说的很清楚，而且对我个人来说，我是很讨厌拿个弹计算器 POC 一打，然后在 Runtime 下个断点就开始分析漏洞调用的文章。这样是无法以更高的层次去审视漏洞的。

所以在这里我汇总几个漏洞点的触发图，希望给看这个系列文章，或正在学习和调试 Struts2 漏洞的朋友一个更清晰的理解思路。

## 生命周期

![img](https://oss.javasec.org/images/struts2-sum-1.jpg)

通过上图可以看出，漏洞的出现一般位于请求刚进入框架时拦截器的解析，和在渲染结果时对标签、参数的处理。

## 漏洞位置

![img](https://oss.javasec.org/images/1625284624414.jpg)

一个字，遍地开花。

## 触发点图

![img](https://oss.javasec.org/images/struts2-sum-2.jpg)

入口点仅示范性的写了几个。

# 0x04 漏洞成因

这里简单描述一下对于 Struts2 历史上的 RCE 的漏洞成因是什么。

## 来自不可信源的数据解析

Struts2 把来自命名空间、参数名、参数值、Cookie 值、文件上传文件名等等由攻击者可以控制的字段进行了解析，而中间可能没有进行安全校验和过滤，从而导致了安全漏洞。

## 逻辑上的二次解析

由于 Struts2 提供的对部分标签、配置的解析支持，允许程序在处理过程中使用 OGNL 解析其中部分变量的内容，而在用户配置不当的情况下，可能会导致二次解析，导致 OGNL 注入。

## 使用包含脆弱性的第三方组件

由于使用了 Xstream 和 Jackson 用来支持 xml 和 json 格式的参数，但是却未进行安全功能的限制，导致 Struts2 遭受了来自这两个组件安全风险的威胁。

## 沙箱和正则防御的绕过

Struts2 在 OGNL 注入防御上的步子是一步一步走的，而且是小碎步，官方根据安全人员的报告不停的在修修补补，更新正则，在绕过与修复中不断轮回，直到官方的修复越来越底层。但是即使是现在，官方也还是采取黑名单的方式，每当安全研究人员发掘了一个新思路，官方就把相应的包放在了黑名单中。


# 0x05 触发点

各个漏洞的漏洞触发点表面上大有不同，但是实际上在底层的调用是相同的。这一 part 用来给 RASP/IAST 积累一些思路。详见触发点图。

Struts2 依赖 OGNL 包完成表达式的解析，而 Struts2 调用 OGNL 包中的类位于 `com.opensymphony.xwork2.ognl`。看包路径可以知道，这实际上是 xwork2 的包，struts2 想要调用 OGNL 完成解析，就需要经过这个包下的类。

所以 Struts2 中全部有关 OGNL 的 RCE，sink 点都应该在这个包下，出了这个包，就是 OGNL 包了。但其实 Struts2 依赖 OGNL ，如果对 OGNL 包内的类进行 Hook 也完全没问题，但是一是很难与 source 点进行关联了，二是点下的太深进 Hook 点次数太多，可能影响效率，这个位置见仁见智。

话说回 Struts2，在 Struts2 调用 OGNL 这几个类下，我们重点关注几个类，第一个是 ValueStack 以及他的实现类 OgnlValueStack，因为在 Struts2 中这个类会作为 OGNL 解析的 ROOT 对象。作为 Root 对象里面存储了一些必要的信息，并且提供了解析参数等功能。

这些功能在实际上是依赖 OgnlUtil 来完成，这个工具类是 Struts2 与 Ognl 交互的最后一公里，Struts2 想要调用 OGNL ，就应该必须使用这个类，这个类提供了 `getValue()` 与 `setValue()`  两个必备的解析方法，以及一个 `callMethod()` 方法。最后，这几个方法都通过 OgnlUtil 的内部类 OgnlTask 的 execute 方法调用 OGNL 包内的方法进行解析，所以其实这里最好的 Hook 点应该是 OgnlUtil.OgnlTask 的 execute 方法。

出了 Struts2 就进入了 OGNL 包，调用逃不出 ognl.Ognl 的 `getValue()` 与 `setValue()` 方法，并且在解析前，会使用 parseExpression 将表达式解析成节点树。因此想要在 Ognl 包中下点，就下这三个点就可以了。

在将表达式解析成节点后，ognl 会依次调用每个子节点进行各自的处理逻辑，其中对于一些子节点，例如我们经常看到的 ASTChain、ASTMethod、ASTStaticMethod 等，他们的 `setValue()` 方法也会调用 `getValue()` 方法，因此其实最终的漏洞触发点就只有一个，那就是子节点的 `getValue()`  方法。

如果表达式中涉及到了方法调用，最终会由 OgnlRuntime 的 `callMethod` 和 `callStaticMethod` 方法，调用 `callAppropriateMethod` 方法进行判断和校验后，由 `invokeMethod` 方法进行调用。

以上就是对 Struts2 OGNL 表达式触发点的解析了，在这系列漏洞的研究过程中，我们经常会看见 `TextParseUtil.translateVariables()` 、`UrlProvider.findString()`、`Component.findString()` 等等方法最终导致了漏洞的产生，而这些点其实都是中间调用点，最终的触发点还是在我们刚才说的那几个里面。


# 0x06 触发逻辑

在对 OGNL 注入漏洞进行利用的时候，除了直接写表达式之外，我们还使用了一些技巧。

## 多条表达式执行

在构造 Struts2 payload 的过程中，通常我们需要进行很多操作，这种情况需要我们一次执行多个表达式。

**ASTSequence：**`one,two`

使用逗号分隔多个表达式，多个表达式依次调用。

**ASTEval：**`(one)(two)`

多个表达式使用括号括起来，会分别执行，但同时这里会对 one 进行二次解析。

**ASTChain：**`(one).(two)`

使用链式调用的方式，会对每个括号内的进行解析并执行。


**三目运算：**`one?two:three`

由 PKAV 发在 wooyun 中的姿势，原文链接：http://drops.wooyun.org/papers/16875，在网上好像讨论较少。这种情况下也会对表达式依次执行。


## 二次解析

在某些版本 Struts2 中，为了绕过参数名的校验，或者为了对字符串进行二次解析，我们需要使用 OGNL 在解析过程中的一些特性。

**TOP 关键字：**`top['foo'](0)`

OGNL 使用 top 关键字可以访问第一个元素，在上面的写法，会对中括号中的字符串进行二次解析。

**ASTEval：**`(one)(two)`

ASTEval 写法会对 one 进行二次解析。


## 触发点差异

在之前的触发点中讨论过，对于 ognl 包来说，触发的方式就两种，一种的 setValue，一种是 getValue。而我们使用的漏洞利用方式的 setValue 会取其中的节点调用 getValue。也就是说，其实最终的触发点就只有一个，那就是 getValue。

对于 getValue 触发点的 payload，如果想用在 setValue 的触发点中，就要在外面再包裹一层，解析时将 payload 解析成其中的节点，再进行 getValue。

而包裹的方式使用 OGNL 调用的任意一个即可。例如二次解析中的 `(one)(two)`，可以在外面包裹一层 `three[(one)(two)]`，依旧是对 one 的二次解析。

# 0x07 攻防历史

对于 Struts2 漏洞攻防的历史，写出来可真是一部大戏，在研究过程中，我翻阅了现网大部分的复现和分析文章，其中 Lucifaer 的[这篇文章](https://lucifaer.com/2019/01/16/%E6%B5%85%E6%9E%90OGNL%E7%9A%84%E6%94%BB%E9%98%B2%E5%8F%B2/)写的清楚明白，大家可以进行参阅，我这里就不再机械的描述整个过程，在漏洞分析和调试的过程中我也有对版本更新和防护绕过的讨论，可以在其中进行查看。

在这章中，我单单凭借自己的理解从意识流上分析一下官方在这个周期中进行的安全防护。

结合整个漏洞分析过程，以及生命周期和触发点图，我们可以看到，官方对于 OGNL 注入的防护集中于三个位置：
1. Source 点，也就是导致漏洞的参数最初的入口点，这个点通常是在拦截器中。
2. Struts2 包中调用 ognl 包的最后一公里，包括 OgnlUtil、ValueStack、SecurityMemberAccess 等类。
3. ognl 包中执行方法之前。

一开始，官方采取了你打我补的方式，使用正则对来自参数、Cookie 等攻击者可控的部分进行了处理，这种处理方式包括黑名单正则、白名单正则、过滤正则等，修修补补又一年，从哪里进来的恶意参数，就在哪补，这种修补流于表面，而且治标不治本。

后来官方也发现这种方式不太靠谱，在 Struts2 包中调用 OGNL 的地方进行修复，自定义了一个 DefaultMemberAccess 的子类 SecurityMemberAccess 进行安全验证，并在里面对一些禁止调用的包和类进行了黑名单处理，对于这个类的覆盖和里面属性的清空的攻防姿势又来来回回拉扯了几次。

再到后来官方真的无奈了，直接删除了 DefaultMemberAccess，并且下到 ognl 包中，在调用方法之前，把一些黑名单类直接写死在判断代码里。

通过这一系列过程我们可以看到，Struts2 官方对于漏洞的修复和安全意识的进步几乎完全依赖于安全研究者的通报，没有从开发的过程中去思考在某些位置使用解析会不会导致什么安全问题，所以我觉得如果有人有那个闲情逸致把我上面写的点都 sink 一下的话，再挖个 RCE 的入口点几乎还是没什么难度的。


# 0x08 一些 PAYLOADS

在前几章的演示中，一直使用 Runtime 或者 ProcessBuilder 弹计算器来实施漏洞的调试，在实战中，还可以有更多的选择，这里我尝试收集了一些小 payload，基本上都是常见的利用方式：

## 获取请求参数

可能使用请求参数的值来绕过防御

```
#param
#parameters.param[0]
```

## 文件上传

所谓文件上传实际上就是文件写入，以下 payload 从请求中获取参数

```
#fos=new java.io.FileOutputStream(#req.getParameter("filename"))
#fos.write(#req.getParameter("filecontext").getBytes())
#fos.close()
```

链式调用写法
```
new java.io.BufferedWriter(new java.io.FileWriter("filepath")).append(#req.getParameter("filecontent")).close()
```

## request/response 对象

获取 request 对象
```
#request=@org.apache.struts2.ServletActionContext@getRequest()
#request=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletRequest")
```
获取 response 对象
```
#response=@org.apache.struts2.ServletActionContext@getResponse()
#response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse")
```

## 命令执行

```
@java.lang.Runtime@getRuntime().exec('payload')
new java.lang.ProcessBuilder(new java.lang.String[]{"payload"}).start()
```

## 回显

一般都通过 response 对象来回显，可以 getWriter 写进去。

```
#writer=response.getWriter()
#writer.println("result")
#writer.flush()
#writer.close()
```

或 addHeader 加在响应头部都可以。
```
#response.addHeader("result",result);
```


以上的 payload 仅仅是网上比较常见的，但是其实还有多种实现方式，不局限于这几种，灵活搭配这些 payload，结合我们之前提到的各种不同的触发逻辑，再结合在漏洞调试中我们发现的 unicode 编码等特性，可以使 Struts2 的 payload 诡谲多变，不易被检测出来。
