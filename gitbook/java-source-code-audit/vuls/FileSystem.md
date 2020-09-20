# 恶意文件访问类漏洞

## 读文件

示例-存在恶意文件读取漏洞代码：

示例-存在恶意文件读取漏洞代码：

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

#### 1.1.1 同级目录任意文件读取漏洞测试

攻击者通过传入恶意的`name`参数可以读取服务器中的任意文件，如下图：

