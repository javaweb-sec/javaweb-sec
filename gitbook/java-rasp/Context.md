# RASP Context

RASP会在Http请求抵达Web应用服务器的时候自动创建RASP Context（RASP上下文，存储了Http请求和响应对象request、response、RASP防御规则、请求参数、RASP防御记录等重要数据），并在该Http请求结束时自动清理RASP Context。



## RASP劫持Servlet/Filter对象原理

RASP内置了`javax.servlet.Servlet`和`javax.servlet.Filter`接口的Hook方法，Servlet容器中的任何Servlet或Filter在被调用之前都被RASP插入了劫持代码。RASP通过劫持`javax.servlet.Servlet`的`service`方法和`javax.servlet.Filter`类的`doFilter`方法不但可以获取到原始的`HttpServletRequest`和`HttpServletResponse`对象，还可以控制Servlet和Filter的程序执行逻辑，从而让RASP能够控制整个Http请求的生命周期。

**RASP劫持Servlet/Filter对象原理：**

![img](https://oss.javasec.org/images/image-20201202170149095.png)



**RASPHttpRequestContextManager：**

![img](https://oss.javasec.org/images/image-20201203164721652.png)

当Servlet或Filter请求结束后会调用`RASPHttpRequestContextManager#finishHook`清理RASP Context中的缓存数据。



## RASP Context与防御模块之间的关系

RASP在分析Web攻击的时候通常都会使用Hook技术捕获程序执行时的关键参数信息，然后和RASP的上下文中缓存的请求参数进行关联分析，使用基于攻击行为的分析方式分析出请求的参数中是否包含了恶意攻击。

因为RASP Context中存储着当前线程中所有与Http请求相关联的对象，所以在任意的RASP防御模块中都可以随时随地的获取到Http请求的参数、请求方式、请求文件绝对路径、URL地址等重要数据，同时RASP还会在Context中存储当前线程中的Http请求中的攻击信息，在Servlet或Filter的生命周期结束时将攻击日志写入本地日志文件并清理Context中的缓存对象。