# Java Web 基础

`Java EE`指的是Java平台企业版（`Java Platform Enterprise Edition`），之前称为`Java 2 Platform, Enterprise Edition `(`J2EE`)，2017 年的 9 月Oracle将`Java EE` 捐赠给 Eclipse 基金会，由于Oracle持有Java商标原因，Eclipse基金于2018年3月将`Java EE`更名为[Jakarta EE](https://jakarta.ee/)。

## Java EE版本

[Java EE历史版本](https://zh.wikipedia.org/wiki/Java_Servlet)：

| Java SE/JDK版本 | Java EE版本 | Servlet版本 | 发布时间         |
| --------------- | ----------- | ----------- | ---------------- |
| /               | /           | Servlet 1.0 | (1997年6月)      |
| JDK1.1          | /           | Servlet 2.0 | /                |
| /               | /           | Servlet 2.1 | (1998年11月)     |
| JDK1.2          | J2EE 1.2    | Servlet 2.2 | (1999年12月12日) |
| JDK1.2          | J2EE 1.3    | Servlet 2.3 | (2001年9月24日)  |
| JDK1.3          | J2EE 1.4    | Servlet 2.4 | (2003年11月11日) |
| JDK1.5          | Java EE 5   | Servlet 2.5 | (2006年5月11日)  |
| JDK1.6          | Java EE 6   | Servlet 3.0 | (2009年12月10日) |
| /               | Java EE 7   | Servlet 3.1 | (2013年5月28日)  |
| /               | Java EE 8   | Servlet 4.0 | (2017年8月31日)  |
| /               | Jakarta EE8 | Servlet 4.0 | (2019年8月26日)  |

由上表可知`Java EE`并不是`Java SE`的一部分(JDK不自带)，`Java EE`的版本也不完全是对应了JDK版本，我们通常最为关注的是`Java EE`对应的`Servlet`版本。不同的`Servlet`版本有着不一样的特性，`Servlet容器`(如`GlassFish/Tomcat/Jboss`)也会限制部署的`Servlet`版本。Java流行的`Spring MVC`(基于Servlet机制实现)、`Struts2`(基于Filter机制实现)等Web框架也是基于不同的`Java EE`版本封装了各自的框架。



## Java Web 模块化开发

如今的较为大型的 Java Web 项目通常都采用了模块化方式开发，借助于`Maven`、`Gradle`依赖管理工具，Java可以非常轻松的完成模块化开发。除此之外使用`OSGi`(`Open Service Gateway Initiative` 可实现模块热部署)技术开发来Java动态模块化系统也是较为常见的。

> 采用模块化开发也会给我们做代码审计带来一定的难度，因为需要在更多的依赖库中去寻找需要我们审计的代码

使用Maven开发的 JavaWeb 项目示例:

![img](/Users/yz/IdeaProjects/javaweb-sec/gitbook/images/12.png)

