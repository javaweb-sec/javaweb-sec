# Request & Response

在`B/S架构`中最重要的就是浏览器和服务器端交互，`Java EE`将其封装为`请求`和`响应对象`，即 `request(HttpServletRequest)` 和 `response(HttpServletResponse)`。

`HttpServletRequest `对象用于处理来自客户端的请求，当客户端通过HTTP协议访问服务器时，HTTP 中的所有信息都封装在这个对象中，通过`HttpServletRequest `对象可以获取到客户端请求的所有信息。

`HttpServletResponse`对象用于响应客户端的请求，通过`HttpServletResponse`对象可以处理服务器端对客户端请求响应。

## `HttpServletRequest `常用方法

| 方法                            | 说明                                       |
| ------------------------------- | ------------------------------------------ |
| getParameter(String name)       | 获取请求中的参数，该参数是由name指定的     |
| getParameterValues(String name) | 返回请求中的参数值，该参数值是由name指定的 |
| getRealPath(String path)        | 获取Web资源目录                            |
| getAttribute(String name)       | 返回name指定的属性值                       |
| getAttributeNames()             | 返回当前请求的所有属性的名字集合           |
| getCookies()                    | 返回客户端发送的Cookie                     |
| getSession()                    | 获取session回话对象                        |
| getInputStream()                | 获取请求主题的输入流                       |
| getReader()                     | 获取请求主体的数据流                       |
| getMethod()                     | 获取发送请求的方式，如GET、POST            |
| getParameterNames()             | 获取请求中所有参数的名称                   |
| getRemoteAddr()                 | 获取客户端的IP地址                         |
| getRemoteHost()                 | 获取客户端名称                             |
| getServerPath()                 | 获取请求的文件的路径                       |

## `HttpServletResponse `常用方法

| 方法                                 | 说明                                 |
| ------------------------------------ | ------------------------------------ |
| getWriter()                          | 获取响应打印流对象                   |
| getOutputStream()                    | 获取响应流对象                       |
| addCookie(Cookie cookie)             | 将指定的Cookie加入到当前的响应中     |
| addHeader(String name,String value)  | 将指定的名字和值加入到响应的头信息中 |
| sendError(int sc)                    | 使用指定状态码发送一个错误到客户端   |
| sendRedirect(String location)        | 发送一个临时的响应到客户端           |
| setDateHeader(String name,long date) | 将给出的名字和日期设置响应的头部     |
| setHeader(String name,String value)  | 将给出的名字和值设置响应的头部       |
| setStatus(int sc)                    | 给当前响应设置状态码                 |
| setContentType(String ContentType)   | 设置响应的MIME类型                   |