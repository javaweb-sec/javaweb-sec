# Java Web 基础

`Java EE`指的是Java平台企业版（`Java Platform Enterprise Edition`），之前称为`Java 2 Platform, Enterprise Edition `(`J2EE`)，2017 年的 9 月Oracle将`Java EE` 捐赠给 Eclipse 基金会，由于Oracle持有Java商标原因，Eclipse基金于2018年3月将`Java EE`更名为[Jakarta EE](https://jakarta.ee/)。



## Java EE和Servlet版本

[Java EE 历史版本](https://en.wikipedia.org/wiki/Jakarta_EE)：

| 平台版本       | 发布日期   | 规范    | Java SE支持            | 重要变化                                                     |
| -------------- | ---------- | ------- | ---------------------- | ------------------------------------------------------------ |
| Jakarta EE 10  | 2022-09-13 | 10      | Java SE 17, Java SE 11 | 移除Servlet、Faces、CDI和EJB (Entity Beans和Embeddable Container)中的过时项，CDI-Build Time。 |
| Jakarta EE 9.1 | 2021-05-25 | 9.1     | Java SE 11, Java SE 8  | JDK 11支持                                                   |
| Jakarta EE 9   | 2020-12-08 | 9       | Java SE 8              | API命名空间从javax移动到jakarta                              |
| Jakarta EE 8   | 2019-09-10 | 8       | Java SE 8              | 与Java EE 8完全兼容                                          |
| Java EE 8      | 2017-08-31 | JSR 366 | Java SE 8              | 基于CDI的安全性和HTTP/2                                      |
| Java EE 7      | 2013-05-28 | JSR 342 | Java SE 7              | WebSocket、JSON和HTML5支持                                   |
| Java EE 6      | 2009-12-10 | JSR 316 | Java SE 6              | CDI托管Bean和REST                                            |
| Java EE 5      | 2006-05-11 | JSR 244 | Java SE 5              | Java注解                                                     |
| J2EE 1.4       | 2003-11-11 | JSR 151 | J2SE 1.4               | WS-I可互操作的Web服务                                        |
| J2EE 1.3       | 2001-09-24 | JSR 58  | J2SE 1.3               | Java连接器架构                                               |
| J2EE 1.2       | 1999-12-17 | 1.2     | J2SE 1.2               | 最初的规范发布                                               |

[Servlet 历史版本](https://zh.wikipedia.org/wiki/Java_Servlet)：

| Servlet API版本       | 发布时间      | 规范             | 平台                 | 重要变更                                                   |
| --------------------- | ------------- | ---------------- | -------------------- | ---------------------------------------------------------- |
| Jakarta Servlet 6.0   | 2022年5月31日 | 6.0              | Jakarta EE 10        | 移除已弃用功能并实现请求的增强                             |
| Jakarta Servlet 5.0   | 2020年10月9日 | 5.0              | Jakarta EE 9         | 将API从javax.servlet包移动到jakarta.servlet                |
| Jakarta Servlet 4.0.3 | 2019年9月10日 | 4.0              | Jakarta EE 8         | 从"Java"商标更名为Jakarta                                  |
| Java Servlet 4.0      | 2017年9月     | JSR 369          | Java EE 8            | HTTP/2                                                     |
| Java Servlet 3.1      | 2013年5月     | JSR 340          | Java EE 7            | 非阻塞I/O、HTTP协议升级机制（WebSocket）                   |
| Java Servlet 3.0      | 2009年12月    | JSR 315          | Java EE 6, Java SE 6 | 可插拔性、易开发性、异步Servlet、安全性、文件上传          |
| Java Servlet 2.5      | 2005年9月     | JSR 154          | Java EE 5, Java SE 5 | 需要Java SE 5，支持注释                                    |
| Java Servlet 2.4      | 2003年11月    | JSR 154          | J2EE 1.4, J2SE 1.3   | web.xml使用XML Schema                                      |
| Java Servlet 2.3      | 2001年8月     | JSR 53           | J2EE 1.3, J2SE 1.2   | 添加了过滤器                                               |
| Java Servlet 2.2      | 1999年8月     | JSR 902, JSR 903 | J2EE 1.2, J2SE 1.2   | 成为J2EE的一部分，在.war文件中引入了独立的Web应用程序      |
| Java Servlet 2.1      | 1998年11月    | 2.1a             | 未指定               | 第一个正式规范，添加了RequestDispatcher、ServletContext    |
| Java Servlet 2.0      | 1997年12月    | —                | JDK 1.1              | 是1998年4月Java Servlet Development Kit 2.0的一部分        |
| Java Servlet 1.0      | 1996年12月    | —                | 未指定               | 是1997年6月Java Servlet Development Kit（JSDK）1.0的一部分 |

由上表可知`Java EE`并不是`Java SE`的一部分(JDK不自带)，`Java EE`的版本也不完全是对应了JDK版本，我们通常最为关注的是`Java EE`对应的`Servlet`版本。不同的`Servlet`版本有着不一样的特性，`Servlet容器`(如`GlassFish/Tomcat/Jboss`)也会限制部署的`Servlet`版本。Java流行的`Spring MVC`(基于Servlet机制实现)、`Struts2`(基于Filter机制实现)等Web框架也是基于不同的`Java EE`版本封装了各自的框架。

[Servlet 3.0 规范](https://download.oracle.com/otndocs/jcp/servlet-3.0-fr-eval-oth-JSpec/)、[Servlet 3.1 规范](https://download.oracle.com/otndocs/jcp/servlet-3_1-fr-eval-spec/index.html)、[Servlet 4.0 规范](https://download.oracle.com/otndocs/jcp/servlet-4-final-spec/index.html)

