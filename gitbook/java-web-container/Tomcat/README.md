# Apache Tomcat

![tomcat](https://oss.javasec.org/images/tomcat-1541484.png)

Apache Tomcat软件是` Java Servlet`、`JavaServer Pages`、`Java Expression Language` 和` Java WebSocket` 技术的开源实现。Tomcat由于其自身简单、稳定、开源等特征，在中小型系统和并发量小的场景下被普遍使用，有极大的用户使用量。

## Tomcat Servlet版本

| Tomcat版本                   | Java EE版本  | Servlet版本 | JSP版本 |
| ---------------------------- | ------------ | ----------- | ------- |
| Tomcat 5.0.0 +               | J2EE 1.4     | Servlet 2.4 | JSP 2.0 |
| Tomcat 6.0.0 - Tomcat 6.0.44 | Java EE 5    | Servlet 2.5 | JSP 2.1 |
| Tomcat 7.0.0 - Tomcat 7.0.25 | Java EE 6    | Servlet 3.0 | JSP 2.2 |
| Tomcat 8.0.0 +               | Java EE 7    | Servlet 3.1 | JSP 2.3 |
| Tomcat 9.0.0 +               | Java EE 8    | Servlet 4.0 | JSP 2.3 |
| Tomcat 10.0.0 +              | Jakarta EE8  | Servlet 5.0 | JSP 3.0 |
| Tomcat 11.0.0 +              | Jakarta EE 9 | Servlet 6.0 | JSP 4.0 |

参考: [Web Application Specifications](https://cwiki.apache.org/confluence/display/TOMCAT/Specifications)、[Apache Tomcat 11](https://tomcat.apache.org/tomcat-11.0-doc/index.html)



## 最新版本

截止2020年09月15日最新版本已经发布到：` 9.0.38`、`10.0.0-M8 alpha`。

Github地址：https://github.com/apache/tomcat

Tomcat官网：https://tomcat.apache.org/

历史版本下载地址：https://archive.apache.org/dist/tomcat/



## 安全漏洞

Tomcat在历史上曾被曝出多种类型的漏洞，这些漏洞将会导致服务器存在较高的安全风险，其中包括但不限于：

- 默认配置
- 弱口令爆破
- 历史安全漏洞
- Tomcat AJP协议
- 如何在利用Tomcat Getshell

