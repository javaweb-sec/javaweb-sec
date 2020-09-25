# Apache Tomcat

Apache Tomcat软件是` Java Servlet`、`JavaServer Pages`、`Java Expression Language` 和` Java WebSocket` 技术的开源实现。

![img](https://tomcat.apache.org/res/images/tomcat.png)



Tomcat由于其开源且轻量的特征，在中小型系统和并发量小的场合下被普遍使用。对于一些中小型网站，将会有大部分开发者使用Tomcat部署其应用。因此，Tomcat具有极大的用户使用量。



## 规范对应版本

| Tomcat版本 | Servlet版本 | JSP版本 |
| ---------- | ----------- | ------- |
| 9.0.X      | 3.1         | 2.3     |
| 7.0.X      | 3.0         | 2.2     |
| 6.0.X      | 2.5         | 2.1     |
| 5.5.X      | 2.4         | 2.0     |
| 4.1.X      | 2.3         | 1.2     |
| 3.3.X      | 2.2         | 1.1     |



## 最新版本

截止目前（2020-09-15），Tomcat已经发布到 9.0.38

Github地址：https://github.com/apache/tomcat

官网：https://tomcat.apache.org/



## 安全漏洞

Tomcat在历史上曾被曝出多种类型的漏洞，这些漏洞将会导致服务器存在较高的安全风险，其中包括但不限于：

- 默认配置
- 弱口令爆破
- 历史安全漏洞
- Tomcat AJP协议
- 如何在利用Tomcat Getshell

