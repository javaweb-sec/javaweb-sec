# JDBC Connection

Java通过`java.sql.DriverManager`来管理所有数据库的驱动注册，所以如果想要建立数据库连接需要先在`java.sql.DriverManager`中注册对应的驱动类，然后调用`getConnection`方法才能连接上数据库。

JDBC定义了一个叫`java.sql.Driver`的接口类负责实现对数据库的连接，所有的数据库驱动包都必须实现这个接口才能够完成数据库的连接操作。`java.sql.DriverManager.getConnection(xx)`其实就是间接的调用了`java.sql.Driver`类的`connect`方法实现数据库连接的。数据库连接成功后会返回一个叫做`java.sql.Connection`的数据库连接对象，一切对数据库的查询操作都将依赖于这个`Connection`对象。

JDBC连接数据库的一般步骤:

1. 注册驱动，`Class.forName("数据库驱动的类名")`。
2. 获取连接，`DriverManager.getConnection(xxx)`。

**JDBC连接数据库示例代码如下:**

```java
String CLASS_NAME = "com.mysql.jdbc.Driver";
String URL = "jdbc:mysql://localhost:3306/mysql"
String USERNAME = "root";
String PASSWORD = "root";

Class.forName(CLASS_NAME);// 注册JDBC驱动类
Connection connection = DriverManager.getConnection(URL, USERNAME, PASSWORD);
```

## 数据库配置信息

传统的Web应用的数据库配置信息一般都是存放在`WEB-INF`目录下的`*.properties`、`*.yml`、`*.xml`中的,如果是`Spring Boot`项目的话一般都会存储在jar包中的`src/main/resources/`目录下。常见的存储数据库配置信息的文件路径如：`WEB-INF/applicationContext.xml`、`WEB-INF/hibernate.cfg.xml`、`WEB-INF/jdbc/jdbc.properties`，一般情况下使用find命令加关键字可以轻松的找出来，如查找Mysql配置信息: `find 路径 -type f |xargs grep "com.mysql.jdbc.Driver"`。

### 为什么需要Class.forName?

很多人不理解为什么第一步必须是`Class.forName(CLASS_NAME);// 注册JDBC驱动类`，因为他们永远不会跟进驱动包去一探究竟。

实际上这一步是利用了Java反射+类加载机制往`DriverManager`中注册了驱动包！

![img](https://oss.javasec.org/images/image-20191208225820692.png)

`Class.forName("com.mysql.jdbc.Driver")`实际上会触发类加载，`com.mysql.jdbc.Driver`类将会被初始化，所以`static静态语句块`中的代码也将会被执行，所以看似毫无必要的`Class.forName`其实也是暗藏玄机的。如果反射某个类又不想初始化类方法有两种途径：

1. 使用`Class.forName("xxxx", false, loader)`方法，将第二个参数传入false。
2. ClassLoader.load("xxxx");

### Class.forName可以省去吗？

连接数据库就必须`Class.forName(xxx)`几乎已经成为了绝大部分人认为的既定事实而不可改变，但是某些人会发现删除`Class.forName`一样可以连接数据库这又作何解释？

实际上这里又利用了Java的一大特性:`Java SPI(Service Provider Interface)`，因为`DriverManager`在初始化的时候会调用`java.util.ServiceLoader`类提供的SPI机制，Java会自动扫描jar包中的`META-INF/services`目录下的文件，并且还会自动的`Class.forName(文件中定义的类)`，这也就解释了为什么不需要`Class.forName`也能够成功连接数据库的原因了。

**Mysql驱动包示例:**

![img](https://oss.javasec.org/images/image-20191208232329364.png)



## JDBC数据库连接总结

使用JDBC连接数据相对于PHP直接使用`mysql_connect/mysqli_connect`函数就可以完成数据库连接来说的确难了很多，但是其中也暗藏了很多Java的特性需要我们去深入理解。

或许您会有所疑问我们为什么非要搞明白`Class.forName`这个问题？这个问题和Java安全有必然的联系吗？其实这里只是想让大家明白`Java反射`、`类加载机制`、和`SPI机制`以及养成阅读JDK或者第三方库代码的习惯，也希望不明白上述机制的朋友深入去理解思考下。

学习完本节后希望您能去思考如下问题：

1. `SPI机制`是否有安全性问题？
2. `Java反射`有那些安全问题？
3. `Java类加载机制`是什么？
4. 数据库连接时密码安全问题？
5. 使用JDBC如何写一个通用的`数据库密码爆破`模块？