# XSS漏洞

攻击者利用XSS(`Cross-site scripting`)漏洞攻击可以在用户的浏览器中执行JS恶意脚本，`XSS`攻击可以实现`用户会话劫持`、`钓鱼攻击`、`恶意重定向`、`点击劫持`、`挂马`、`XSS蠕虫`等，XSS攻击类型分为：`反射型`、`存储型`、`DOM型`。



## 1. 反射型XSS攻击

**示例 - 存在反射型XSS的xss.jsp代码：**

```jsp
<%=request.getParameter("input")%>
```

攻击者通过传入恶意的`input`参数值可以在用户浏览器中注入一段`JavaScript`脚本。

示例 - 注入XSS代码：

```js
<script>alert('xss');</script>
```

浏览器请求：[http://localhost:8000/modules/servlet/xss.jsp?input=%3Cscript%3Ealert(%27xss%27)%3B%3C/script%3E](http://localhost:8000/modules/servlet/xss.jsp?input=%3Cscript%3Ealert(%27xss%27);%3C/script%3E)

![img](https://oss.javasec.org/images/image-20201115123227812.png)



## 2. 存储型XSS攻击

**示例 - 存在存储型XSS的guestbook.jsp代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.*" %>
<%
    String username = request.getParameter("username");
    String content = request.getParameter("content");

    String guestBookKey = "GUEST_BOOK";
    List<Map<String, String>> comments = new ArrayList<Map<String, String>>();

    if (content != null) {
        Object obj = application.getAttribute(guestBookKey);

        if (obj != null) {
            comments = (List<Map<String, String>>) obj;
        }

        Map<String, String> comment = new HashMap<String, String>();
        String              ip      = request.getHeader("x-real-ip");

        if (ip == null) {
            ip = request.getRemoteAddr();
        }

        comment.put("username", username);
        comment.put("content", content);
        comment.put("ip", ip);
        comment.put("date", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));

        comments.add(comment);

        application.setAttribute(guestBookKey, comments);
    }
%>
<html>
<head>
    <title>留言板</title>
</head>
<style>
    * {
        margin: 0;
        padding: 0;
    }
</style>
<body>
<div style="border: 1px solid #C6C6C6;">
    <div style="text-align: center;">
        <h2>在线留言板</h2>
    </div>
    <div>
        <dl>
            <%
                Object obj = application.getAttribute(guestBookKey);

                if (obj instanceof List) {
                    comments = (List<Map<String, String>>) obj;

                    for (Map<String, String> comment : comments) {
            %>
            <dd>
                <div style="min-height: 50px; margin: 20px; border-bottom: 1px solid #9F9F9F;">
                    <p><B><%=comment.get("username")%>
                    </B>[<%=comment.get("ip")%>] 于 <%=comment.get("date")%> 发表回复：</p>
                    <p style="margin: 15px 0 5px 0; font-size: 12px;">
                    <pre><%=comment.get("content")%></pre>
                    </p>
                </div>
            </dd>
            <%
                    }
                }
            %>
        </dl>
    </div>
    <div style="background-color: #fff; border: 1px solid #C6C6C6;">
        <form action="#" method="POST" style="margin: 20px;">
            昵称: <input type="text" name="username" style="width:250px; height: 28px;"/><br/><br/>
            <textarea name="content" style="overflow: auto;width: 100%; height: 250px;"></textarea>
            <input type="submit" value="提交留言" style="margin-top: 20px; width: 80px; height: 30px;"/>
        </form>
    </div>
</div>
</body>
</html>
```

访问：[http://10.10.99.2:8000/modules/servlet/guestbook.jsp](http://10.10.99.2:8000/modules/servlet/guestbook.jsp)，并在留言内容出填入xss测试代码，如下：

![img](https://oss.javasec.org/images/image-20201115123648353.png)

提交留言后页面会刷新，并执行留言的xss代码：

![img](https://oss.javasec.org/images/image-20201115123711964.png)

## 3. DOM XSS

**示例 - dom.jsp代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
Date: <span style="color: red;"></span>
<input type="hidden" value="<%=request.getParameter("date")%>" />
<script>
    var date = document.getElementsByTagName("input")[0].value;
    document.getElementsByTagName("span")[0].innerHTML = date;
</script>
```

正常请求测试：[http://localhost:8000/modules/servlet/dom.jsp?date=2020-11-15%2015:57:22](http://localhost:8000/modules/servlet/dom.jsp?date=2020-11-15%2015:57:22)

![img](https://oss.javasec.org/images/image-20201115155811063.png)



XSS攻击测试：[http://localhost:8000/modules/servlet/dom.jsp?date=%3Cimg%20src=1%20onerror=alert(/xss/)%20/%3E](http://localhost:8000/modules/servlet/dom.jsp?date=%3Cimg%20src=1%20onerror=alert(/xss/)%20/%3E)

![img](https://oss.javasec.org/images/image-20201115160351831.png)



## 4. XSS防御

XSS最为常见的处理方式是转义特殊字符，后端程序在接受任何用户输入的参数时都应当优先考虑是否会存在XSS攻击。



### 4.1 htmlspecialchars

在PHP中通常会使用[htmlspecialchars](https://www.php.net/htmlspecialchars)函数会将一些可能有攻击威胁的字符串转义为html实体编码，这样可以有效的避免XSS攻击。

**示例 - htmlspecialchars 转义： **

| 字符         | 替换后               |
| :----------- | :------------------- |
| `&` (& 符号) | `&amp;`              |
| `"` (双引号) | `&quot;`             |
| `'` (单引号) | `&#039;`或者`&apos;` |
| `<` (小于)   | `&lt;`               |
| `>` (大于)   | `&gt;`               |

在Java中虽然没有内置如此简单方便的函数，但是我们可以通过字符串替换的方式实现类似`htmlspecialchars`函数的功能。

```java
/**
 * 实现htmlSpecialChars函数把一些预定义的字符转换为HTML实体编码
 *
 * @param content 输入的字符串内容
 * @return HTML实体化转义后的字符串
 */
public static String htmlSpecialChars(String content) {
  if (content == null) {
    return null;
  }

  char[]        charArray = content.toCharArray();
  StringBuilder sb        = new StringBuilder();

  for (char c : charArray) {
    switch (c) {
      case '&':
        sb.append("&amp;");
        break;
      case '"':
        sb.append("&quot;");
        break;
      case '\'':
        sb.append("&#039;");
        break;
      case '<':
        sb.append("&lt;");
        break;
      case '>':
        sb.append("&gt;");
        break;
      default:
        sb.append(c);
        break;
    }
  }

  return sb.toString();
}
```

在存储或者输出请求参数的时候使用该方法过滤即可实现XSS防御。

### 4.2 全局的XSSFilter

```java
package com.anbai.sec.vuls.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;

public class XSSFilter implements Filter {

	@Override
	public void init(FilterConfig filterConfig) {

	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;

		// 创建HttpServletRequestWrapper，包装原HttpServletRequest对象，示例程序只重写了getParameter方法，
		// 应当考虑如何过滤：getParameter、getParameterValues、getParameterMap、getInputStream、getReader
		HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(request) {
			public String getParameter(String name) {
				// 获取参数值
				String value = super.getParameter(name);

				// 简单转义参数值中的特殊字符
				return value.replace("&", "&amp;").replace("<", "&lt;").replace("'", "&#039;");
			}
		};

		chain.doFilter(requestWrapper, resp);
	}

	@Override
	public void destroy() {

	}

}
```

web.xml添加XSSFilter过滤器：

```xml
<!-- XSS过滤器 -->
<filter>
  <filter-name>XSSFilter</filter-name>
  <filter-class>com.anbai.sec.vuls.filter.XSSFilter</filter-class>
</filter>

<filter-mapping>
  <filter-name>XSSFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

请求XSS示例程序：[http://localhost:8000/modules/servlet/xss.jsp?input=%3Cscript%3Ealert(%27xss%27);%3C/script%3E](http://localhost:8000/modules/servlet/xss.jsp?input=%3Cscript%3Ealert(%27xss%27);%3C/script%3E)

![img](https://oss.javasec.org/images/image-20201115164019678.png)

经过全局过滤器转义后的参数就不会再带有XSS攻击能力了。



### 4.3 RASP XSS攻击防御

RASP可以实现类似于全局XSSFilter的请求参数过滤功能，比较稳定的一种方式是Hook到`javax.servlet.ServletRequest`接口的实现类的`getParameter/getParameterValues/getParameterMap`等核心方法，在该方法return之后插入RASP的检测代码。这种实现方案虽然麻烦，但是可以避免触发Http请求参数解析问题（Web应用无法获取`getInputStream`和乱码等问题）。

**示例 - RASP对getParameter返回值Hook示例：**

![img](https://oss.javasec.org/images/image-20201115172732140.png)

反射型的XSS防御相对来说比较简单，直接禁止GET参数中出现`<>`标签，只要出现就理解拦截，如：

```html
http://localhost:8000/modules/servlet/xss.jsp?input=<script>alert('xss');</script>
```

过滤或拦截掉`<>`后`input`参数就不再具有攻击性了。

但是POST请求的XSS参数就没有那么容易过滤了，为了兼顾业务，不能简单的使用`htmlSpecialChars`的方式直接转义特殊字符，因为很多时候应用程序是必须支持HTML标签的（如：`<img>、<h1>`等）。RASP在防御XSS攻击的时候应当尽可能的保证用户的正常业务不受影响，否则可能导致用户无法业务流程阻塞或崩溃。

为了支持一些常用的HTML标签和HTML标签属性，RASP可以通过词法解析的方式，将传入的字符串参数值解析成HTML片段，然后分析其中的标签和属性是否合法即可。

![img](https://oss.javasec.org/images/image-20201115180617209.png)



### 4.4 RASP XSS防御能力测试



#### 4.4.1 恶意的HTML标签属性XSS测试

**示例 - 提交带有XSS攻击的Payload：**

```html
<img src='1.jpg' width='10px' height='10px' onerror='alert(/xss/);' />
```

请求示例地址：[http://localhost:8000/modules/servlet/guestbook.jsp](http://localhost:8000/modules/servlet/guestbook.jsp)，并填写XSS攻击代码，如下图：

![img](https://oss.javasec.org/images/image-20201115181311265.png)

RASP能够正确识别并拦截XSS攻击：

![img](https://oss.javasec.org/images/image-20201115181216802.png)

#### 4.4.2 XSS富文本检测测试

RASP如果要实现精确的XSS检测能力就必须能够正确的识别出用户传入的数据到底是否合法，经过HTML词法分析后RASP能够正确认识用户传入的参数值是否是包含了恶意的HTML标签或者属性。

**示例 - 用户在留言板中带图片回复：**

![img](https://oss.javasec.org/images/image-20201115123956172.png)



**示例 - 用户在留言板中回复被注释的HTML片段：**

![img](https://oss.javasec.org/images/image-20201115124359270.png)

![img](https://oss.javasec.org/images/image-20201115124556231.png)

经测试，RASP对XSS攻击防御能力正常，能够识别合法的HTML和javascript代码（DOM类XSS占不支持）。