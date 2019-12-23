# JNDI

`JNDI(Java Naming and Directory Interface)`是Java提供的`Java 命名和目录接口`。通过调用`JNDI`的`API`应用程序可以定位资源和其他程序对象。`JNDI`是`Java EE`的重要部分，需要注意的是它并不只是包含了`DataSource(JDBC 数据源)`，`JNDI`可访问的现有的目录及服务有:`JDBC`、`LDAP`、`RMI`、`DNS`、`NIS`、`CORBA`。

## JNDI目录服务注册

**[JNDI 查找及其关联的引用](https://docs.oracle.com/cd/E19957-01/819-1553/jndi.html):**

| JNDI 查找名称               | 关联的引用                      |
| --------------------------- | ------------------------------- |
| `java:comp/env`             | 应用程序环境项                  |
| `java:comp/env/jdbc`        | JDBC 数据源资源管理器连接工厂   |
| `java:comp/env/ejb`         | EJB 引用                        |
| `java:comp/UserTransaction` | UserTransaction 引用            |
| `java:comp/env/mail`        | JavaMail 会话连接工厂           |
| `java:comp/env/url`         | URL 连接工厂                    |
| `java:comp/env/jms`         | JMS 连接工厂和目标              |
| `java:comp/ORB`             | 应用程序组件之间共享的 ORB 实例 |