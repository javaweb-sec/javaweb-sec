# Filter

`javax.servlet.Filter`是`Servlet2.3`新增的一个特性,主要用于过滤URL请求，通过Filter我们可以实现URL请求资源权限验证、用户登陆检测等功能。

Filter是一个接口，实现一个Filter只需要重写`init`、`doFilter`、`destroy`方法即可，其中过滤逻辑都在`doFilter`方法中实现。

`Filter`的配置类似于`Servlet`，由`<filter>`和`<filter-mapping>`两组标签组成，如果Servlet版本大于3.0同样可以使用注解的方式配置Filter。

**基于注解实现的Filter示例:**

![img](https://oss.javasec.org/images/18.png)