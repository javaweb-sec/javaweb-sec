# Request & Response

在面对一个Web应用时，除了业务逻辑的处理，更多的时候是在处理通信双方的数据交互，即 request 和 response，而在这里实际上就是 `HttpServletRequest` 和 `HttpServletResponse`，位于 `javax.servlet.http` 下。两者分别实现了 `ServletResponse` 和 `ServletRequest` 接口。

`HttpServletRequest `对象代表客户端的请求，当客户端通过HTTP协议访问服务器时，HTTP 请求头中的所有信息都封装在这个对象中，通过这个对象提供的方法，可以获得客户端请求的所有信息。

`HttpServletResponse`对象代表客户端的响应，通过这个对象提供的方法，可以制定不同的响应，页面输出等服务器返回结果。

`HttpServletRequest `常用方法：

| 方法                            | 说明                                                         |
| ------------------------------- | ------------------------------------------------------------ |
| getAttributeNames()             | 返回当前请求的所有属性的名字集合                             |
| getAttribute(String name)       | 返回name指定的属性值                                         |
| getCookies()                    | 返回客户端发送的Cookie                                       |
| getsession()                    | 返回和客户端相关的session，如果没有给客户端分配session，则返回null |
| getsession(boolean create)      | 返回和客户端相关的session，如果没有给客户端分配session，则创建一个session并返回 |
| getParameter(String name)       | 获取请求中的参数，该参数是由name指定的                       |
| getParameterValues(String name) | 返回请求中的参数值，该参数值是由name指定的                   |
| getCharacterEncoding()          | 返回请求的字符编码方式                                       |
| getContentLength()              | 返回请求体的有效长度                                         |
| getInputStream()                | 获取请求的输入流中的数据                                     |
| getMethod()                     | 获取发送请求的方式，如get、post                              |
| getParameterNames()             | 获取请求中所有参数的名字                                     |
| getProtocol()                   | 获取请求所使用的协议名称                                     |
| getReader()                     | 获取请求体的数据流                                           |
| getRemoteAddr()                 | 获取客户端的IP地址                                           |
| getRemoteHost()                 | 获取客户端的名字                                             |
| getServerName()                 | 返回接受请求的服务器的名字                                   |
| getServerPath()                 | 获取请求的文件的路径                                         |

`HttpServletResponse `常用方法：

| 方法                                 | 说明                                     |
| ------------------------------------ | ---------------------------------------- |
| addCookie(Cookie cookie)             | 将指定的Cookie加入到当前的响应中         |
| addHeader(String name,String value)  | 将指定的名字和值加入到响应的头信息中     |
| containsHeader(String name)          | 返回一个布尔值，判断响应的头部是否被设置 |
| encodeURL(String url)                | 编码指定的URL                            |
| sendError(int sc)                    | 使用指定状态码发送一个错误到客户端       |
| sendRedirect(String location)        | 发送一个临时的响应到客户端               |
| setDateHeader(String name,long date) | 将给出的名字和日期设置响应的头部         |
| setHeader(String name,String value)  | 将给出的名字和值设置响应的头部           |
| setStatus(int sc)                    | 给当前响应设置状态码                     |
| setContentType(String ContentType)   | 设置响应的MIME类型                       |