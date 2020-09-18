# Java Web 基础

`Java EE`指的是Java平台企业版（`Java Platform Enterprise Edition`），之前称为`Java 2 Platform, Enterprise Edition `(`J2EE`)，2017 年的 9 月Oracle将`Java EE` 捐赠给 Eclipse 基金会，由于Oracle持有Java商标原因，Eclipse基金于2018年3月将`Java EE`更名为[Jakarta EE](https://jakarta.ee/)。

## Java EE和Servlet版本

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

[Servlet 3.0 规范](https://download.oracle.com/otndocs/jcp/servlet-3.0-fr-eval-oth-JSpec/)、[Servlet 3.1 规范](https://download.oracle.com/otndocs/jcp/servlet-3_1-fr-eval-spec/index.html)、[Servlet 4.0 规范](https://download.oracle.com/otndocs/jcp/servlet-4-final-spec/index.html)

## Tomcat Servlet版本

| Tomcat版本                   | Java EE版本 | Servlet版本 | JSP版本 | 发布时间                        |
| ---------------------------- | ----------- | ----------- | ------- | ------------------------------- |
| Tomcat 5.0.0 +               | J2EE 1.4    | Servlet 2.4 | JSP 2.0 | (2003年11月24日)                |
| Tomcat 6.0.0 - Tomcat 6.0.44 | Java EE 5   | Servlet 2.5 | JSP 2.1 | (2006年5月11日 - 2007年9月11日) |
| Tomcat 7.0.0 - Tomcat 7.0.25 | Java EE 6   | Servlet 3.0 | JSP 2.2 | (2009年12月10日 - 2011年2月6日) |
| Tomcat 8.0.0 +               | Java EE 7   | Servlet 3.1 | JSP 2.3 | (2013年5月28日)                 |
| Tomcat 9.0.0 +               | Java EE 8   | Servlet 4.0 | JSP 2.3 | (2017年2月5日)                  |
| Tomcat 10.0.0 +              | Jakarta EE8 | Servlet 4.0 | JSP 2.3 | /                               |

参考: [Web Application Specifications](https://cwiki.apache.org/confluence/display/TOMCAT/Specifications)

