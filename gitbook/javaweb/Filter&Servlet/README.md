# Filter和Servlet的总结

对于基于`Filter`和`Servlet`实现的简单架构项目，代码审计的重心集中于找出所有的`Filter`分析其过滤规则，找出是否有做全局的安全过滤、敏感的URL地址是否有做权限校验并尝试绕过`Filter`过滤。第二点则是找出所有的`Servlet`，分析`Servlet`的业务是否存在安全问题,如果存在安全问题是否可以利用？是否有权限访问？利用时是否被Filter过滤等问题，切勿看到`Servlet`、`JSP`中的漏洞点就妄下定论，不要忘了`Servlet`前面很有可能存在一个全局安全过滤的`Filter`。

`Filter`和`Servlet`都是`Java Web`提供的API，简单的总结了下有如下共同点。

1. `Filter`和`Servlet`都需要在`web.xml`或`注解`(`@WebFilter`、`@WebServlet`)中配置，而且配置方式是非常的相似的。
2. `Filter`和`Servlet`都可以处理来自Http请求的请求，两者都有`request`、`response`对象。
3. `Filter`和`Servlet`基础概念不一样，`Servlet`定义是容器端小程序，用于直接处理后端业务逻辑，而`Filter`的思想则是实现对Java Web请求资源的拦截过滤。
4. `Filter`和`Servlet`虽然概念上不太一样，但都可以处理Http请求，都可以用来实现MVC控制器(`Struts2`和`Spring`框架分别基于`Filter`和`Servlet`技术实现的)。
5. 一般来说`Filter`通常配置在`MVC`、`Servlet`和`JSP`请求前面，常用于后端权限控制、统一的Http请求参数过滤(`统一的XSS`、`SQL注入`、`Struts2命令执行`等攻击检测处理)处理，其核心主要体现在请求过滤上，而`Servlet`更多的是用来处理后端业务请求上。
