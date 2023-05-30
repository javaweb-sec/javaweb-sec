# JDBC SQL注入

SQL注入(`SQL injection`)是因为`应用程序`在执行SQL语句的时候没有正确的处理用户输入字符串，将用户输入的恶意字符串拼接到了SQL语句中执行，从而导致了SQL注入。

SQL注入是一种原理非常简单且危害程度极高的恶意攻击，我们可以理解为不同程序语言的注入方式是一样的。

本章节只讨论基于`JDBC`查询的SQL注入，暂不讨论基于`ORM`实现的框架注入，也不会过多的讨论注入的深入用法、函数等。

## SQL注入示例

在SQL注入中如果需要我们手动闭合SQL语句的`'`的注入类型称为`字符型注入`、反之成为`整型注入`。

### 字符型注入

假设程序想通过用户名查询用户个人信息，那么它最终执行的SQL语句可能是这样:

```sql
select host,user from mysql.user where user = '用户输入的用户名'
```

正常情况下用户只需传入自己的用户名，如：`root`，程序会自动拼成一条完整的SQL语句：

```sql
select host,user from mysql.user where user = 'root'
```

查询结果如下:

```sql
mysql> select host,user from mysql.user where user = 'root';
+-----------+------+
| host      | user |
+-----------+------+
| localhost | root |
+-----------+------+
1 row in set (0.00 sec)
```

但假设黑客传入了恶意的字符串:**`root' and 1=2 union select 1,'2`**去闭合SQL语句，那么SQL语句的含义将会被改变：

```sql
select host,user from mysql.user where user = 'root' and 1=2 union select 1,'2'
```

查询结果如下:

```sql
mysql> select host,user from mysql.user where user = 'root' and 1=2 union select 1,'2';
+------+------+
| host | user |
+------+------+
| 1    | 2    |
+------+------+
1 row in set (0.00 sec)
```

Java代码片段如下:

```java
// 获取用户传入的用户名
String user = request.getParameter("user");

// 定义最终执行的SQL语句，这里会将用户从请求中传入的host字符串拼接到最终的SQL
// 语句当中，从而导致了SQL注入漏洞。
String sql = "select host,user from mysql.user where user = '" + user + "'";

// 创建预编译对象
PreparedStatement pstt = connection.prepareStatement(sql);

// 执行SQL语句并获取返回结果对象
ResultSet rs = pstt.executeQuery();
```

如上示例程序，sql变量拼接了我们传入的用户名字符串并调用`executeQuery`方法执行了含有恶意攻击的SQL语句。我们只需要在用户传入的`user`参数中拼凑一个能够闭合SQL语句又不影响SQL语法的恶意字符串即可实现SQL注入攻击！需要我们使用`'(单引号)`闭合的SQL注入漏洞我们通常叫做`字符型SQL注入`。

#### 快速检测字符串类型注入方式

在渗透测试中我们判断字符型注入点最快速的方式就是在参数值中加`'(单引号)`,如:`http://localhost/1.jsp?id=1'`，如果页面返回500错误或者出现异常的情况下我们通常可以初步判定该参数可能存在注入。

### 字符型注入测试

示例程序包含了一个存在字符型注入的Demo，测试时请自行修改数据库账号密码，`user`参数参数存在注入。

**sql-injection.jsp：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.sql.*" %>
<%@ page import="java.io.StringWriter" %>
<%@ page import="java.io.PrintWriter" %>
<style>
    table {
        border-collapse: collapse;
    }

    th, td {
        border: 1px solid #C1DAD7;
        font-size: 12px;
        padding: 6px;
        color: #4f6b72;
    }
</style>
<%!
    // 数据库驱动类名
    public static final String CLASS_NAME = "com.mysql.jdbc.Driver";

    // 数据库链接字符串
    public static final String URL = "jdbc:mysql://localhost:3306/mysql?autoReconnect=true&zeroDateTimeBehavior=round&useUnicode=true&characterEncoding=UTF-8&useOldAliasMetadataBehavior=true&useOldAliasMetadataBehavior=true&useSSL=false";

    // 数据库用户名
    public static final String USERNAME = "root";

    // 数据库密码
    public static final String PASSWORD = "root";

    Connection getConnection() throws SQLException, ClassNotFoundException {
        Class.forName(CLASS_NAME);// 注册JDBC驱动类
        return DriverManager.getConnection(URL, USERNAME, PASSWORD);
    }

%>
<%
    String user = request.getParameter("user");

    if (user != null) {
        Connection connection = null;

        try {
            // 建立数据库连接
            connection = getConnection();

            // 定义最终执行的SQL语句，这里会将用户从请求中传入的host字符串拼接到最终的SQL
            // 语句当中，从而导致了SQL注入漏洞。
//            String sql = "select host,user from mysql.user where user = ? ";
            String sql = "select host,user from mysql.user where user = '" + user + "'";
            out.println("SQL:" + sql);
            out.println("<hr/>");

            // 创建预编译对象
            PreparedStatement pstt = connection.prepareStatement(sql);
//            pstt.setObject(1, user);

            // 执行SQL语句并获取返回结果对象
            ResultSet rs = pstt.executeQuery();

            out.println("<table><tr>");
            out.println("<th>主机</th>");
            out.println("<th>用户</th>");
            out.println("<tr/>");

            // 输出SQL语句执行结果
            while (rs.next()) {
                out.println("<tr>");

                // 获取SQL语句中查询的字段值
                out.println("<td>" + rs.getObject("host") + "</td>");
                out.println("<td>" + rs.getObject("user") + "</td>");
                out.println("<tr/>");
            }

            out.println("</table>");

            // 关闭查询结果
            rs.close();

            // 关闭预编译对象
            pstt.close();
        } catch (Exception e) {
            // 输出异常信息到浏览器
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            out.println(sw);
        } finally {
            // 关闭数据库连接
            connection.close();
        }

    }
%>
```

正常请求，查询用户名为`root`的用户信息测试:

http://localhost:8080/sql-injection.jsp?user=root

![img](https://oss.javasec.org/images/image-20191214232846579.png)

提交含有`'(单引号)`的注入语句测试：

http://localhost:8080/sql-injection.jsp?user=root'

![img](https://oss.javasec.org/images/image-20191214233050147.png)

如果用户屏蔽了异常信息的显示我们就无法直接通过页面信息确认是否是注入，但是我们可以通过后端响应的状态码来确定是否是注入点，如果返回的状态码为`500`，那么我们就可以初步的判定`user`参数存在注入了。

提交读取Mysql用户名和版本号注入语句测试：

http://localhost:8080/sql-injection.jsp?user=root' and 1=2 union select user(),version() --%20

![img](https://oss.javasec.org/images/image-20191214234010523.png)

这里使用了`-- (--空格，空格可以使用%20代替)`来注释掉SQL语句后面的`'(单引号)`，当然我们同样也可以使用`#(井号，URL传参的时候必须传URL编码后的值：%23)`注释掉`'`。

### 整型注入

假设我们执行的SQL语句是：

```sql
select id, username, email from sys_user where id = 用户ID
```

查询结果如下:

```sql
mysql> select id, username, email from sys_user where id = 1;
+----+----------+-------------------+
| id | username | email             |
+----+----------+-------------------+
|  1 | yzmm     | admin@javaweb.org |
+----+----------+-------------------+
1 row in set (0.01 sec)
```

假设程序预期用户输入一个数字类型的参数作为查询条件，且输入内容未经任何过滤直接就拼到了SQL语句当中，那么也就产生了一种名为`整型SQL注入`的漏洞。

对应的程序代码片段：

```java
// 获取用户传入的用户ID
String id = request.getParameter("id");

// 定义最终执行的SQL语句，这里会将用户从请求中传入的host字符串拼接到最终的SQL
// 语句当中，从而导致了SQL注入漏洞。
String sql = "select id, username, email from sys_user where id =" + id;

// 创建预编译对象
PreparedStatement pstt = connection.prepareStatement(sql);

// 执行SQL语句并获取返回结果对象
ResultSet rs = pstt.executeQuery();
```

#### 快速检测整型注入方式

整型注入相比字符型更容易检测，使用参数值添加`'(单引号)`的方式或者使用`运算符`、`数据库子查询`、`睡眠函数(一定慎用！如：sleep)`等。

检测方式示例：

```sql
id=2-1
id=(2)
id=(select 2 from dual)
id=(select 2)
```

盲注时不要直接使用`sleep(n)`！例如: `id=sleep(3)`

对应的SQL语句`select username from sys_user where id = sleep(3)`

执行结果如下：

```sql
mysql> select username from sys_user where id= sleep(3);
Empty set (24.29 sec)
```

为什么只是sleep了3秒钟最终变成了24秒？因为sleep语句执行了`select count(1) from sys_user`遍！当前`sys_user`表因为有8条数据所以执行了8次。

如果非要使用sleep的方式可以使用子查询的方式代替：

```sql
id=2 union select 1, sleep(3)
```

查询结果如下：

```sql
mysql> select username,email from sys_user where id=1 union select 1, sleep(3);
+----------+-------------------+
| username | email             |
+----------+-------------------+
| yzmm     | admin@javaweb.org |
| 1        | 0                 |
+----------+-------------------+
2 rows in set (3.06 sec)
```



## SQL注入防御

既然我们学会了如何提交恶意的注入语句，那么我们到底应该如何去防御注入呢？通常情况下我们可以使用以下方式来防御SQL注入攻击：

1. 转义用户请求的参数值中的`'(单引号)`、`"(双引号)`。
2. 限制用户传入的数据类型，如预期传入的是数字，那么使用:`Integer.parseInt()/Long.parseLong`等转换成整型。
3. 使用`PreparedStatement`对象提供的SQL语句预编译。

切记只过滤`'(单引号)`或`"(双引号)`并不能有效的防止整型注入，但是可以有效的防御字符型注入。解决注入的根本手段应该使用参数预编译的方式。

### PreparedStatement SQL预编译查询

将上面存在注入的Java代码改为`?(问号)`占位的方式即可实现SQL预编译查询。

示例代码片段：

```java
// 获取用户传入的用户ID
String id = request.getParameter("id");

// 定义最终执行的SQL语句，这里会将用户从请求中传入的host字符串拼接到最终的SQL
// 语句当中，从而导致了SQL注入漏洞。
String sql = "select id, username, email from sys_user where id =? ";

// 创建预编译对象
PreparedStatement pstt = connection.prepareStatement(sql);

// 设置预编译查询的第一个参数值
pstt.setObject(1, id);

// 执行SQL语句并获取返回结果对象
ResultSet rs = pstt.executeQuery();
```

需要特别注意的是并不是使用`PreparedStatement`来执行SQL语句就没有注入漏洞，而是将用户传入部分使用`?(问号)`占位符表示并使用`PreparedStatement`预编译SQL语句才能够防止注入！

### JDBC预编译

可能很多人都会有一个疑问：`JDBC`中使用`PreparedStatement`对象的`SQL语句`究竟是如何实现预编译的？接下来我们将会以Mysql驱动包为例，深入学习`JDBC`预编译实现。

`JDBC`预编译查询分为客户端预编译和服务器端预编译，对应的URL配置项是:`useServerPrepStmts`，当`useServerPrepStmts`为`false`时使用客户端(驱动包内完成SQL转义)预编译，`useServerPrepStmts`为`true`时使用数据库服务器端预编译。

#### 数据库服务器端预编译

JDBC URL配置示例:

```java
jdbc:mysql://localhost:3306/mysql?autoReconnect=true&zeroDateTimeBehavior=round&useUnicode=true&characterEncoding=UTF-8&useOldAliasMetadataBehavior=true&useOldAliasMetadataBehavior=true&useSSL=false&useServerPrepStmts=true
```

代码片段:

```java
String sql = "select host,user from mysql.user where user = ? ";
PreparedStatement pstt = connection.prepareStatement(sql);
pstt.setObject(1, user);
```

使用`JDBC`的`PreparedStatement`查询数据包如下：

![img](https://oss.javasec.org/images/image-20191215011503098.png)

#### 客户端预编译

JDBC URL配置示例:

```java
jdbc:mysql://localhost:3306/mysql?autoReconnect=true&zeroDateTimeBehavior=round&useUnicode=true&characterEncoding=UTF-8&useOldAliasMetadataBehavior=true&useOldAliasMetadataBehavior=true&useSSL=false&useServerPrepStmts=false
```

代码片段:

```java
String sql = "select host,user from mysql.user where user = ? ";
PreparedStatement pstt = connection.prepareStatement(sql);
pstt.setObject(1, user);
```

使用`JDBC`的`PreparedStatement`查询数据包如下：

![img](https://oss.javasec.org/images/image-20191215011935278.png)

对应的Mysql客户端驱动包预编译代码在`com.mysql.jdbc.PreparedStatement`类的`setString`方法，如下：

![image-20191215012554164](https://oss.javasec.org/images/image-20191215012554164.png)

预编译前的值为`root'`,预编译后的值为`'root\''`，和我们通过`WireShark`抓包的结果一致。

#### Mysql预编译

Mysql默认提供了预编译命令:`prepare`,使用`prepare`命令可以在Mysql数据库服务端实现预编译查询。

**`prepare`查询示例：**

```sql
prepare stmt from 'select host,user from mysql.user where user = ?';
set @username='root';
execute stmt using @username;
```

查询结果如下：

```mysql
mysql> prepare stmt from 'select host,user from mysql.user where user = ?';
Query OK, 0 rows affected (0.00 sec)
Statement prepared

mysql> set @username='root';
Query OK, 0 rows affected (0.00 sec)

mysql> execute stmt using @username;
+-----------+------+
| host      | user |
+-----------+------+
| localhost | root |
+-----------+------+
1 row in set (0.00 sec)
```

## JDBC SQL注入总结

本章节通过浅显的方式学习了`JDBC`中的`SQL注入`漏洞基础知识和防注入方式，希望大家能够从本章节中了解到SQL注入的本质，在后续章节也将讲解`ORM`中的SQL注入。