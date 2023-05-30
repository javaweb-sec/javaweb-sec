# 文件访问类漏洞

本章节将讲解与Java文件或目录访问安全性问题，常见的Java文件操作相关的漏洞大致有如下类型：

1. 任意目录遍历
2. 任意文件、目录复制
3. 任意文件读取/下载
4. 任意文件、目录修改/重命名
5. 任意文件、目录删除
6. ......

我们通常把这类漏洞归为一个类型，因为产生漏洞的原因都是因为程序对文件或目录访问控制不严、程序内部逻辑错误导致的任意文件或目录恶意访问漏洞。

## 1. 任意文件读取

任意文件读写漏洞即因为没有验证请求的资源文件是否合法导致的，此类漏洞在Java中有着较高的几率出现，任意文件读取漏洞原理很简单，但一些知名的中间件：`Weblogic`、`Tomcat`、`Resin`又或者是主流MVC框架:`Spring MVC`、`Struts2`都存在此类漏洞。

**示例 - 存在恶意文件读取漏洞代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.FileInputStream" %>

<pre>
<%
    File file = new File(request.getRealPath("/") + request.getParameter("name"));
    FileInputStream in = new FileInputStream(file);
    int tempbyte;

    while ((tempbyte = in.read()) != -1) {
        out.write(tempbyte);
    }

    in.close();
%>
</pre>
```



### 1.1 同级目录任意文件读取漏洞测试

攻击者通过传入恶意的`name`参数可以读取服务器中的任意文件:[http://localhost:8000/modules/filesystem/FileInputStream.jsp?name=./index.jsp](http://localhost:8000/modules/filesystem/FileInputStream.jsp?name=./index.jsp)，如下图：

![img](https://oss.javasec.org/images/image-20200920222742568.png)



### 1.2 读取WEB-INF/web.xml测试

当攻击者通过传入恶意的`name`参数值为`WEB-INF/web.xml`时可以读取Web应用的配置信息，请求：[http://localhost:8000/modules/filesystem/FileInputStream.jsp?name=WEB-INF/web.xml](http://localhost:8000/modules/filesystem/FileInputStream.jsp?name=WEB-INF/web.xml)，如下图：

![img](https://oss.javasec.org/images/image-20200920223143227.png)



### 1.3 跨目录读取敏感文件测试

开发人员通常使用文件名、文件后缀、文件目录进行拼接的方式来获取待操作文件的绝对路径并进行相关操作，在这种情况下，攻击者如果想要查看服务器中的其他目录，则会使用 `../` 进行目录的跨越，常使用的操作是跨越目录到服务根目录，再向下寻找文件。例如`../../../../../../../../etc/passwd`。

请求：[http://localhost:8000/modules/filesystem/FileInputStream.jsp?name=../../../../../../../../../../../../etc/passwd](http://localhost:8000/modules/filesystem/FileInputStream.jsp?name=../../../../../../../../../../../../etc/passwd)，如下图：

![img](https://oss.javasec.org/images/image-20200920223741823.png)



## 2. 写文件

示例 - 存在恶意文件写入漏洞的代码：

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.FileOutputStream" %>

<%
    File file = new File(request.getParameter("f"));
    FileOutputStream fos = new FileOutputStream(file);
    fos.write(request.getParameter("c").getBytes());
    fos.flush();
    fos.close();

    out.println(file.getAbsoluteFile() + "\t" + file.exists());
%>
```



### 2.1 跨目录写入文件测试

攻击者可能期望跨目录写入文件，如写入 SSH KEY、写入计划任务等等方式进行进一步的攻击。

请求：[http://localhost:8000/modules/filesystem/file-w.jsp?f=../../a.rar&c=aaa](http://localhost:8000/modules/filesystem/file-w.jsp?f=../../a.rar&c=aaa)，如下图：

![img](https://oss.javasec.org/images/image-20200920224145502.png)



### 2.2 绝对路径写入文件测试

攻击者通过传入恶意的参数`f`和`c`参数可以使用绝对路径在服务器上写入恶意的`WebShell`后门或其他文件，请求：[http://localhost:8000/modules/filesystem/file-w.jsp?f=/tmp/2.txt&c=webshell](http://localhost:8000/modules/filesystem/file-w.jsp?f=/tmp/2.txt&c=webshell)，如下图：

![img](https://oss.javasec.org/images/image-20200920224445145.png)



## 3. 删除文件

### 3.1 任意文件删除测试

**示例 - 存在任意文件删除漏洞代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%
    File file = new File(request.getParameter("file"));
    out.println(file.delete());
%>
```

攻击者通过参入`file`参数即可删除服务器中的任意文件：

![img](https://oss.javasec.org/images/image-20200920224910717.png)



### 3.2 FileSystem任意文件删除测试

**示例 - 存在任意文件删除漏洞代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%@ page import="java.lang.reflect.Method" %>

<%
    String file = request.getParameter("file");

    Method m = Class.forName("java.io.DefaultFileSystem").getMethod("getFileSystem");
    m.setAccessible(true);
    Object fs = m.invoke(null);

    Method m2 = fs.getClass().getMethod("delete", File.class);
    m2.setAccessible(true);
    out.print(m2.invoke(fs, new File(file)));
%>
```

攻击者通过参入`file`参数即可删除服务器中的任意文件：

![img](https://oss.javasec.org/images/image-20200920225130413.png)

攻击者通过反射调用 Filesystem 并执行` delete`方法，用来绕过对 File 对象 `delete`方法的防御。



## 4. 文件/目录复制、移动

**示例 - 存在任意文件复制漏洞代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.nio.file.Path" %>
<%@ page import="java.nio.file.Paths" %>
<pre>
<%
    try {
        Path path = Files.copy(Paths.get(request.getParameter("source")), Paths.get(request.getParameter("dest")));

        out.println(path);
    } catch (IOException e) {
        e.printStackTrace();
    }
%>
</pre>
```

攻击者传入恶意的`source`和`dest`参数可以实现复制任何文件到任意的目录，比如攻击者可以在用户中心上传一张内容为`WebShell`恶意代码的`1.jpg`图片文件，然后通过漏洞将`1.jpg`图片文件，复制到同级目录并更新名称为`1.jsp`的可解析脚本文件，访问`1.jsp`文件即可实现控制服务器的目的，如下图：

![img](https://oss.javasec.org/images/image-20200920225531504.png)

在实际环境中，应用系统可能根据需求在配置文件如`web.xml`中或代码层面如`filter`设置某些目录（如上传目录、资源目录等）禁止对 `.jsp` 脚本文件等可执行文件进行解析，因此，攻击者需要将恶意文件移动或复制到其他能够执行的目录进行解析。请求：[http://localhost:8000/modules/filesystem/files-copy.jsp?source=/tmp/1.jsp&dest=/Users/yz/Desktop/apache-tomcat-8.5.31/webapps/ROOT/1.jsp](http://localhost:8000/modules/filesystem/files-copy.jsp?source=/tmp/1.jsp&dest=/Users/yz/Desktop/apache-tomcat-8.5.31/webapps/ROOT/1.jsp)，如下图：

![image-20200920225852244](https://oss.javasec.org/images/image-20200920225852244.png)



## 5. 重命名文件

**示例 - 存在文件名重命名漏洞代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%
    String fileName1 = request.getParameter("s");
    String fileName2 = request.getParameter("d");

    File f = new File(fileName1);
    File d = new File(fileName2);

    f.renameTo(d);

    out.println(d + "\t" + d.exists());
%>
```

攻击者传入恶意的`s`和`d`参数即可将文件名为`1.txt`的文本文件重命名为`1.jsp`可执行脚本文件，请求：[http://localhost:8000/modules/filesystem/file-rename.jsp?s=/tmp/1.txt&d=/tmp/1.jsp](http://localhost:8000/modules/filesystem/file-rename.jsp?s=/tmp/1.txt&d=/tmp/1.jsp)，如下图：

![img](https://oss.javasec.org/images/image-20200920230047497.png)

攻击者会使用重命名的方式将（txt、jpg等资源文件）重命名为可执行脚本文件（jsp）来获得`webshell`从而控制Web应用系统，并绕过某些安全防护机制。常见的攻击手段是在文件上传时，上传包含恶意代码的图片文件，再利用重命名将其转为可执行的脚本文件。



## 6. 文件目录遍历

任意目录遍历漏洞顾名思义攻击者可以通过漏洞遍历出服务器操作系统中的任意目录文件名，从而导致服务器敏感信息泄漏，某些场景下(如遍历出网站日志、备份文件、管理后台等)甚至可能会导致服务器被非法入侵。

**示例 - 存在任意目录遍历代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>

<pre>
<%
    String[] files = new File(request.getParameter("dir")).list();

    for (String file : files) {
        out.println(file);
    }
%>
</pre>
```

这个漏洞可能由Web应用本身的开发不规范导致，也有可能是因为`MVC框架`、`项目依赖的第三方库`、`Web服务器自身`导致的。如果是由于自身开发不规范导致的那么需要程序严格控制用户传入目录参数是否合法！

### 6.1 相对目录遍历测试

攻击者传入`dir`参数即可遍历出对应目录的所有文件，[http://localhost:8000/modules/filesystem/file-list.jsp?dir=../](http://localhost:8000/modules/filesystem/file-list.jsp?dir=../)，如下图：

![img](https://oss.javasec.org/images/image-20200920230351094.png)

由于攻击者传入的`dir`参数值为相对路径，可能是多级目录名称，也可能只是一个非常简单的`../`上级目录，大部分的`WAF`并不能精准识别这类攻击。



### 6.2 绝对目录遍历测试

当攻击者可以传入绝对路径进行攻击时，路径中将不会存在`../`等穿越目录特征，很多WAF将无法攻击阻拦，请求：[http://localhost:8000/modules/filesystem/file-list.jsp?dir=/etc](http://localhost:8000/modules/filesystem/file-list.jsp?dir=/etc)，如下图：

![img](https://oss.javasec.org/images/image-20200920230839578.png)

## 7. IO和NIO.2的文件系统支持

### 7.1 使用NIO任意文件读取漏洞测试

**示例 - 存在任意文件读取的NIO.2代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.nio.file.Paths" %>
<pre>
<%
    try {
        byte[] bytes = Files.readAllBytes(Paths.get(request.getParameter("file")));
        out.println(new String(bytes));
    } catch (IOException e) {
        e.printStackTrace();
    }
%>
</pre>
```

攻击者传入恶意的`file`即可读取服务器中的任意文件：

![img](https://oss.javasec.org/images/image-20200920231108351.png)



## 8. 任意文件/目录访问漏洞修复

### 8.1 限制读取目录或文件

在读取文件或者目录的时候我们需要考虑到文件读取安全问题，严格控制用户传入参数，禁止或限制用户传入文件路径。

**检测用户参数合法性代码示例(请根据具体业务需求调整判定逻辑):**

```jsp
<%@ page import="java.io.File" %><%--
  Created by IntelliJ IDEA.
  User: yz
  Date: 2019/12/4
  Time: 6:08 下午
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%!
    // 定义限制用户遍历的文件目录常量
    private static final String IMAGE_DIR = "/data/images/";
%>
<%
    // 定义需要遍历的目录
    String dirStr = request.getParameter("dir");

    if (dirStr != null) {
        File dir = new File(dirStr);

        // 获取文件绝对路径，转换成标准的文件路径
        String fileDir = (dir.getAbsoluteFile().getCanonicalFile() + "/").replace("\\\\", "/").replaceAll("/+", "/");
        out.println("<h3>" + fileDir + "</h3>");

        // 检查当前用户传入的目录是否包含在系统限定的目录下
        if (fileDir.startsWith(IMAGE_DIR)) {
            File[] dirs = dir.listFiles();

            out.println("<pre>");

            for (File file : dirs) {
                out.println(file.getName());
            }

            out.println("</pre>");
        } else {
            out.println("目录不合法!");
        }
    }

%>
```

请求遍历非系统限制的目录示例：

![img](https://oss.javasec.org/images/image-20191204185103785.png)

### 8.2 RASP防御恶意文件访问攻击

RASP可以使用Agent机制实现Hook任意的Java类API，因此可以轻易的捕获到Java程序读取的任意文件路径。RASP可以将Hook到的文件路径和Http请求的参数进行关联分析，检测Java读取的文件路径是否会受到Http请求参数的控制，如果发现请求参数最终拼接到了文件路径中应当立即阻断文件访问行为，并记录攻击日志。

为了提升RASP的防御能力，应当将Java SE中的所有与文件读写相关的最为底层的Java API类找出来，然后添加监视点。

**Java底层操作IO的类API表（<=JDK14）**

| 类名                                 | 类型      | 重要方法                                                     |
| ------------------------------------ | --------- | ------------------------------------------------------------ |
| `java.io.WinNTFileSystem`            | `java.io` | `delete/list/createDirectory/rename/setLastModifiedTime/listRoots` |
| `java.io.UnixFileSystem`             | `java.io` | `delete/list/createDirectory/rename/setLastModifiedTime/listRoots` |
| `java.io.FileInputStream`            | `java.io` | `open/read`                                                  |
| `java.io.FileOutputStream`           | `java.io` | `open/write`                                                 |
| `java.io.RandomAccessFile`           | `java.io` | `read/write/seek`                                            |
| `sun.nio.ch.FileChannelImpl`         | `sun.nio` | `open/read/map/transferTo0`                                  |
| `sun.nio.ch.FileDispatcher`          | `sun.nio` | `read/pread/readv/write/pwrite/writev/seek`                  |
| `sun.nio.ch.SocketDispatcher`        | `sun.nio` | `read/readv/write/writev`                                    |
| `sun.nio.ch.DatagramDispatcher`      | `sun.nio` | `read/readv/write/writev`                                    |
| `sun.nio.fs.UnixNativeDispatcher`    | `sun.nio` | `fopen/read/write/getcwd/link/unlink/rename/mkdir/chown`     |
| `sun.nio.fs.WindowsNativeDispatcher` | `sun.nio` | `fopen/read/write/getcwd/link/unlink/rename/mkdir/chown`     |
| `sun.nio.fs.UnixCopyFile`            | `sun.nio` | `copy/copyDirectory/copyFile/move/copyLink/copySpecial/transfer` |
| `sun.nio.ch.IOUtil`                  | `sun.nio` | `read/write/randomBytes`                                     |

**Java IO 底层API关系图**

![img](https://oss.javasec.org/images/image-20201113121413510.png)

**RASP防御思路：**

![img](https://oss.javasec.org/images/image-20201112225033039.png)

当RASP检测到恶意的文件访问后会立即阻断文件读取：

![img](https://oss.javasec.org/images/image-20201113223619874.png)



#### 8.2.1 禁止文件名空字节访问

在低版本的JDK中允许文件名中包含`空字节`（俗称%00截断），为了防止该问题，RASP应当在任何文件被访问的时候检测文件名是否包含了空字节，如果有应当立即终止文件的访问。

**检测文件名空字节示例代码：**

```java
/**
 * 检查文件名中是否包含了空字节，禁止出现%00字符截断
 *
 * @param file 访问文件
 * @return 是否包含空字节
 */
private static boolean nullByteValid(File file) {
        return file.getName().indexOf('\u0000') < 1;
        }
```



#### 8.2.2 禁止写入动态脚本文件

为了避免Web应用被写入恶意的WebShell后门文件，RASP应当在Web应用启动后禁止任何动态脚本的写入操作。在任何与写入文件相关的Java底层方法执行前都应当检测写入的文件后缀是否合法。

禁止写入如下类型的动态脚本文件：

`jsp,jspx,jspa,jspf,asp,asa,cer,aspx,php`

文件写入检测应当处理各类文件写入事件，如：`写文件、重命名文件、复制/移动文件、移动目录`；RASP设置Hook点时也应当严格处理上述IO操作的类文件（一个都不能漏掉，漏掉一个几乎等于全功尽弃），如果新版本的JDK新增或修改了底层IO操作类应当做同步支持。



#### 8.2.3 文件名和请求参数关联分析

RASP应当分析Hook到的文件路径和请求参数的关联性，分析每一个参数是否对最终Hook到的文件路径有必然的关联关系。

如传入的某个参数最终和Hook到的文件路径完全一致，那么应当立即禁止文件访问请求，因为即便用户请求的不是恶意文件也肯定是一个存在任意文件读取漏洞的业务功能，攻击者可以修改传入的参数实现读取服务器中的任意文件。



#### 8.2.4 文件名检测规则和黑名单

攻击者在验证文件读取类漏洞时通常会使用一些常用的技巧和路径，如：`WEB-INF/web.xml`、`/etc/passwd`、`../../../../../../../etc/passwd`等。RASP应该有一些内置的黑名单和检测规则来防止黑客攻击。



## 9. Java 恶意文件访问审计建议

在审计文件读取功能的时候要非常仔细，或许很容易就会有意想不到的收获！快速发现这类漏洞得方式其实也是非常简单的，在IDEA中的项目中重点搜下如下文件读取的类。

1. **JDK原始的`java.io.FileInputStream`、`java.io.FileOutputStream`类**；
2. **JDK原始的`java.io.RandomAccessFile`类**；
3. **Apache Commons IO提供的`org.apache.commons.io.FileUtils`类**；
4. JDK1.7新增的基于NIO非阻塞异步读取文件的`java.nio.channels.AsynchronousFileChannel`类；
5. JDK1.7新增的基于NIO读取文件的`java.nio.file.Files`类。常用方法如:`Files.readAllBytes`、`Files.readAllLines`；
6. `java.io.File`类的`list`、`listFiles`、`listRoots`、`delete`方法；

除此之外，还可以搜索一下`FileUtil/FileUtils`很有可能用户会封装文件操作的工具类。

## 10. Java 恶意文件访问总结

首先，在Java中任意文件或目录恶意访问漏洞是一种非常常见的高危漏洞！多是因为程序内部逻辑错误或者过于信任用户传入的参数导致的。其次此类漏洞原理简单在渗透测试或代码审计时非常容易发现且漏洞影响重大，因为攻击者可以直接操纵服务器中的文件或目录，所以在程序开发过程中我们应该高度重视编码规范、程序逻辑严谨性防止该漏洞发生。