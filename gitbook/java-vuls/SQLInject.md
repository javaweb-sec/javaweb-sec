# SQL注入漏洞

SQL注入是网络攻击中最为常见的攻击方式，通过向服务器端发送恶意的SQL语句或SQL语句片段注入到服务器端的数据库查询逻辑中，改变原有的查询逻辑，从而实现类恶意读取服务器数据库数据，攻击者甚至可以利用数据库内部函数或缺陷`提升权限`，从而获取服务器权限。

## 1. 用户后台系统登陆注入

### 1.1 登陆位置注入测试

后台登陆系统注入在前些年是非常常见的，我们通常会使用`' or '1'='1`之类的注入语句来构建一个查询结果永为真的SQL，俗称：`万能密码`。

**示例 - 用户登陆注入代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.DriverManager" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.Map" %>

<%
//    MYSQL sys_user示例表，测试时请先创建对应的数据库和表
//
//    CREATE TABLE `sys_user` (
//        `id` int(9) unsigned NOT NULL AUTO_INCREMENT COMMENT '用户ID',
//        `username` varchar(16) NOT NULL COMMENT '用户名',
//        `password` varchar(32) NOT NULL COMMENT '用户密码',
//        `user_avatar` varchar(255) DEFAULT NULL COMMENT '用户头像',
//        `register_time` datetime DEFAULT NULL COMMENT '注册时间',
//        PRIMARY KEY (`id`),
//        UNIQUE KEY `idx_sys_user_username` (`username`) USING BTREE
//    ) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8 COMMENT='系统用户表'
//
//    INSERT INTO `sys_user` VALUES ('1', 'admin', '123456', '/res/images/avatar/default.png', '2020-05-05 17:21:27'), ('2', 'test', '123456', '/res/images/avatar/default.png', '2020-05-06 18:27:10'), ('3', 'root', '123456', '/res/images/avatar/default.png', '2020-05-06 18:28:27'), ('4', 'user', '123456', '/res/images/avatar/default.png', '2020-05-06 18:31:34'), ('5', 'rasp', '123456', '/res/images/avatar/default.png', '2020-05-06 18:32:08');
%>

<%
    String sessionKey = "USER_INFO";
    Object sessionUser = session.getAttribute(sessionKey);

    // 退出登陆
    if (sessionUser != null && "exit".equals(request.getParameter("action"))) {
        session.removeAttribute(sessionKey);
        out.println("<script>alert('再见!');location.reload();</script>");
        return;
    }

    Map<String, String> userInfo = null;

    // 检查用户是否已经登陆成功
    if (sessionUser instanceof Map) {
        userInfo = (Map<String, String>) sessionUser;
        out.println("<p>欢迎回来:" + userInfo.get("username") + ",ID:" + userInfo.get("id") + " \r<a href='?action=exit'>退出登陆</a></p>");
        return;
    }

    String username = request.getParameter("username");
    String password = request.getParameter("password");

    // 处理用户登陆逻辑
    if (username != null && password != null) {
        userInfo = new HashMap<String, String>();
        ResultSet  rs         = null;
        Connection connection = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/javaweb-bbs", "root", "root");

            String sql = "select id,username,password from sys_user where username = '" + username + "' and password = '" + password + "'";
            System.out.println(sql);

            rs = connection.prepareStatement(sql).executeQuery();

            while (rs.next()) {
                userInfo.put("id", rs.getString("id"));
                userInfo.put("username", rs.getString("username"));
                userInfo.put("password", rs.getString("password"));
            }

            // 检查是否登陆成功
            if (userInfo.size() > 0) {
                // 设置用户登陆信息
                session.setAttribute(sessionKey, userInfo);

                // 跳转到登陆成功页面
                response.sendRedirect(request.getServletPath());
            } else {
                out.println("<script>alert('登陆失败，账号或密码错误!');history.back(-1)</script>");
            }
        } catch (Exception e) {
            out.println("<script>alert('登陆失败，服务器异常!');history.back(-1)</script>");
        } finally {
            // 关闭数据库连接
            if (rs != null)
                rs.close();

            if (connection != null)
                connection.close();
        }

        return;
    }
%>
<html>
<head>
    <title>Login Test</title>
</head>
<body>
<div style="margin: 30px;">
    <form action="#" method="POST">
        Username:<input type="text" name="username" value="admin"/><br/>
        Password:<input type="text" name="password" value="'=0#"/><br/>
        <input type="submit" value="登陆"/>
    </form>
</div>
</body>
</html>
```

**sys_user表结构如下：**

| id   | username | password | user_avatar                    | register_time       |
| ---- | -------- | -------- | ------------------------------ | ------------------- |
| 1    | admin    | 123456   | /res/images/avatar/default.png | 2020-05-05 17:21:27 |
| 2    | test     | 123456   | /res/images/avatar/default.png | 2020-05-06 18:27:10 |

访问示例中的后台登陆地址：[http://localhost:8000/modules/jdbc/login.jsp](http://localhost:8000/modules/jdbc/login.jsp)，如下图：

![img](https://oss.javasec.org/images/image-20200920235228799.png)

攻击者通过在密码参数处输入：`'=0#`即可使用SQL注入的方式改变查询逻辑，绕过密码认证并登陆系统，因此用于检测用户账号密码是否存在的SQL语句变成了：

`select id,username,password from sys_user where username = 'admin' and password = ''=0#'`

其中的`password`的值预期是传入用户密码，但是实际上被攻击者传入了可改变查询逻辑的SQL语句，将运算结果改变为`true`，从而攻击者可以使用错误的用户及密码登陆系统，如下图：

![img](https://oss.javasec.org/images/image-20200920235312260.png)

毫无疑问因为攻击者输入的信息足够的短小简洁，但是对于用户网站系统来说却有极强的杀伤性，绝大多数的`WAF`或者`RASP`产品都无法精准辨别`'=0#`的威胁性，无法正确做到精准防御。

**万能密码登陆注入原理图解：**

![image-20201114153113439](https://oss.javasec.org/images/image-20201114153113439.png)



## 2. 文章详情页注入

通常情况下在用户系统发布文章后会在数据库中产生一条记录，并生成一个固定的文章ID，用户浏览文章信息只需要传入文章ID，即在后端通过文章ID查询文章详情信息。

**示例 - 存在SQL注入的文章详情代码：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.DriverManager" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.Map" %>

<%
//    MYSQL sys_article示例表，测试时请先创建对应的数据库和表
//    CREATE TABLE `sys_article` (
//        `id` int(11) unsigned NOT NULL AUTO_INCREMENT COMMENT '文章ID',
//        `user_id` int(9) NOT NULL COMMENT '用户ID',
//        `title` varchar(100) NOT NULL COMMENT '标题',
//        `author` varchar(16) NOT NULL COMMENT '作者',
//        `content` longtext NOT NULL COMMENT '文章内容',
//        `publish_date` datetime NOT NULL COMMENT '发布时间',
//        `click_count` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '文章点击数量',
//        PRIMARY KEY (`id`),
//        KEY `index_title` (`title`) USING BTREE
//    ) ENGINE=InnoDB AUTO_INCREMENT=100002 DEFAULT CHARSET=utf8 COMMENT='系统文章表';
//
//    INSERT INTO `sys_article` VALUES ('100000', '1', '东部战区陆军：丢掉幻想，准备打仗！', 'admin', '<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n   中国人民解放军东部战区陆军微信公众号“人民前线”4月15日发布《丢掉幻想，准备打仗！ 》，以下为文章全文：\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n    文丨陈前线\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n    “丢掉幻想，准备斗争！”\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n 这是新中国成立前夕，毛主席发表的一篇文章标题。\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n  毛主席曾说过： “我们爱好和平，但以斗争求和平则和平存，以妥协求和平则和平亡。 ”\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;text-align:center;\">\n  <img src=\"/res/images/20200415203823695.jpg\" />\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n    放眼今日之中国，九州大地上热潮迭涌。 在中国梦的指引下，华夏儿女投身祖国各项建设事业，追赶新时代发展的脚步。 中国在国际上的影响力显著增强，“向东看”开始成为一股潮流。\n</p>', '2020-04-19 17:35:06', '4'), ('100001', '1', '面对战争，时刻准备着！', 'admin', '<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n    这话是20年前，我的新兵连长说的。\n</p>\n<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n  &emsp;&emsp;那是我们授衔后的第一个晚上，班长一脸神秘地说：“按照惯例，今天晚上肯定要紧急集合的，这是你们的‘成人礼’。”于是，熄灯哨音响过之后，我们都衣不解带地躺在床上。班长为了所谓的班级荣誉，也默认了我们的做法。\n</p>\n<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n  &emsp;&emsp;果然，深夜一阵急促的哨音响起，我们迅速打起被包，冲到指定地点集合。大个子连长看着整齐的队伍，说了句：“不错，解散!”一个皆大欢喜的局面。我们都高高兴兴地回到宿舍，紧绷的神经一下子放松下来，排房里很快就响起了呼噜声。\n</p>\n<p align=\"center\" style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;\">\n  <img src=\"/res/images/20200419133156232.jpg\" alt=\"500\" />\n</p>\n<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n  &emsp;&emsp;可是，令人没有想到的是，睡梦中又一阵急促的哨音划破夜空的宁静——连长再次拉起了紧急集合。这一次，情况就完全不一样了，毫无准备的我们，狼狈不堪，有的被包来不及打好，不得不用手抱住;有的找不到自己的鞋子，光脚站在地上，有的甚至连裤子都穿反了……\n</p>', '2020-04-19 17:37:40', '17');
%>

<%
    String id = request.getParameter("id");
    Map<String, Object> articleInfo = new HashMap<String, Object>();
    ResultSet rs = null;
    Connection connection = null;

    if (id != null) {
        try {
            Class.forName("com.mysql.jdbc.Driver");
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/javaweb-bbs", "root", "root");

            String sql = "select * from sys_article where id = " + id;
            System.out.println(sql);

            rs = connection.prepareStatement(sql).executeQuery();

            while (rs.next()) {
                articleInfo.put("id", rs.getInt("id"));
                articleInfo.put("user_id", rs.getInt("user_id"));
                articleInfo.put("title", rs.getString("title"));
                articleInfo.put("author", rs.getString("author"));
                articleInfo.put("content", rs.getString("content"));
                articleInfo.put("publish_date", rs.getDate("publish_date"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 关闭数据库连接
            if (rs != null)
                rs.close();

            if (connection != null)
                connection.close();
        }
    }
%>
<html>
<head>
    <title><%=articleInfo.get("title")%></title>
</head>
<body>
<div style="margin: 30px;">
    <h2 style="height: 30px; text-align: center;"><%=articleInfo.get("title")%></h2>
    <p>作者：<%=articleInfo.get("author")%> - <%=articleInfo.get("publish_date")%></p>
    <div style="border: 1px solid #C6C6C6;">
        <%=articleInfo.get("content")%>
    </div>
</div>
</body>
</html>
```

**sys_article表结构如下：**

| id     | user_id | title                              | author | content  | publish_date        | click_count |
| ------ | ------- | ---------------------------------- | ------ | -------- | ------------------- | ----------- |
| 100000 | 1       | 东部战区陆军：丢掉幻想，准备打仗！ | admin  | 文章内容 | 2020-04-19 17:35:06 | 4           |
| 100001 | 1       | 面对战争，时刻准备着！             | admin  | 文章内容 | 2020-04-19 17:37:40 | 17          |

访问示例程序并传入参数`id=100001`后会显示文章详情，请求：[http://localhost:8000/modules/jdbc/article.jsp?id=100001](http://localhost:8000/modules/jdbc/article.jsp?id=100001)，如下图：

![img](https://oss.javasec.org/images/image-20200920235726634.png)



### 2.1 union select类型的SQL注入攻击测试

攻击者在ID处构造并传入恶意的SQL注入语句后，可以轻松的读取出数据库信息，如将请求中的`id`参数值改为`100001 and 1=2 union select 1,2,user(),version(),database(),6,7`,服务器端将会返回数据库名称、请求：[http://localhost:8000/modules/jdbc/article.jsp?id=100001%20and%201=2%20union%20select%201,2,user(),version(),database(),6,7](http://localhost:8000/modules/jdbc/article.jsp?id=100001%20and%201=2%20union%20select%201,2,user(),version(),database(),6,7)，如下图：

![image-20200921000001434](https://oss.javasec.org/images/image-20200921000001434.png)

由于攻击的Payload中包含了`union、select、user()、version()、database()`敏感关键字，大部分的`WAF`都能够识别此类SQL注入。



### 2.2 算数运算结果探测型攻击测试

但如果攻击者将注入语句改为检测语句:`100001-1`的时候页面会输出文章`id`为`100000`的文章，由于`id`参数存在注入，数据库最终查询到的文章`id`为`100001-1`也就是`id`为`100000`的文章，请求：[http://localhost:8000/modules/jdbc/article.jsp?id=100001-1](http://localhost:8000/modules/jdbc/article.jsp?id=100001-1)，如下图：

![img](https://oss.javasec.org/images/image-20200921000100433.png)

几乎可以绕过`99%`的`WAF`和大部分的`RASP`产品了，此类SQL注入攻击属于不具有攻击性的探测性攻击。



### 2.3 数据库函数型攻击测试

部分攻击者使用了数据库的一些特殊函数进行注入攻击，可能会导致`WAF`无法识别，但是RASP具备特殊函数注入攻击的精准检测和防御能力。

例如上述示例中攻击者传入的`id`参数值为:`(100001-1)`或者`(100001)`用于探测数据表中是否存在`id`值为`100000`的文章，请求：[http://localhost:8000/modules/jdbc/article.jsp?id=(100001)](http://localhost:8000/modules/jdbc/article.jsp?id=(100001))，如下图：

![img](https://oss.javasec.org/images/image-20200921000250818.png)

或者传入的`id`参数值为:`(select 100000)`来探测数据库是否存在`id`值为`100000`的文章，请求：[http://localhost:8000/modules/jdbc/article.jsp?id=(select%20100000)](http://localhost:8000/modules/jdbc/article.jsp?id=(select%20100000))，如下图：

![image-20200921000501695](https://oss.javasec.org/images/image-20200921000501695.png)

大多数数据库支持使用`()`来包裹一个整数型的字段值，但是`99%`的`WAF`和极大多数的`RASP`产品是无法识别此类型的注入攻击的。



## 3. SQL注入 - JSON传参测试

**示例 - 存在SQL注入漏洞的代码示例(JSON传参方式)：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.DriverManager" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.Map" %>
<%@ page import="com.alibaba.fastjson.JSON" %>
<%@ page import="org.apache.commons.io.IOUtils" %>
<%@ page import="com.alibaba.fastjson.JSONObject" %>

<%
    //    MYSQL sys_user示例表，测试时请先创建对应的数据库和表
//
//    CREATE TABLE `sys_user` (
//        `id` int(9) unsigned NOT NULL AUTO_INCREMENT COMMENT '用户ID',
//        `username` varchar(16) NOT NULL COMMENT '用户名',
//        `password` varchar(32) NOT NULL COMMENT '用户密码',
//        `user_avatar` varchar(255) DEFAULT NULL COMMENT '用户头像',
//        `register_time` datetime DEFAULT NULL COMMENT '注册时间',
//        PRIMARY KEY (`id`),
//        UNIQUE KEY `idx_sys_user_username` (`username`) USING BTREE
//    ) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8 COMMENT='系统用户表'
//
//    INSERT INTO `sys_user` VALUES ('1', 'admin', '123456', '/res/images/avatar/default.png', '2020-05-05 17:21:27'), ('2', 'test', '123456', '/res/images/avatar/default.png', '2020-05-06 18:27:10'), ('3', 'root', '123456', '/res/images/avatar/default.png', '2020-05-06 18:28:27'), ('4', 'user', '123456', '/res/images/avatar/default.png', '2020-05-06 18:31:34'), ('5', 'rasp', '123456', '/res/images/avatar/default.png', '2020-05-06 18:32:08');
%>

<%
    String contentType = request.getContentType();

    // 只接受JSON请求
    if (contentType != null && contentType.toLowerCase().contains("application/json")) {
        String     content  = IOUtils.toString(request.getInputStream());
        JSONObject json     = JSON.parseObject(content);
        String     username = json.getString("username");
        String     password = json.getString("password");

        // 处理用户登陆逻辑
        if (username != null && password != null) {
            ResultSet           rs         = null;
            Connection          connection = null;
            Map<String, Object> userInfo   = new HashMap<String, Object>();

            try {
                Class.forName("com.mysql.jdbc.Driver");
                connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/javaweb-bbs", "root", "root");

                String sql = "select * from sys_user where username = '" + username + "' and password = '" + password + "'";
                System.out.println(sql);

                rs = connection.prepareStatement(sql).executeQuery();

                while (rs.next()) {
                    userInfo.put("id", rs.getString("id"));
                    userInfo.put("username", rs.getString("username"));
                    userInfo.put("password", rs.getString("password"));
                    userInfo.put("user_avatar", rs.getString("user_avatar"));
                    userInfo.put("register_time", rs.getDate("register_time"));
                }

                // 检查是否登陆成功
                if (userInfo.size() > 0) {
                    // 设置用户登陆信息
                    out.println(JSON.toJSONString(userInfo));
                } else {
                    out.println("<script>alert('登陆失败，账号或密码错误!');history.back(-1)</script>");
                }
            } catch (Exception e) {
                e.printStackTrace();
                out.println("<script>alert('登陆失败，服务器异常!');history.back(-1)</script>");
            } finally {
                // 关闭数据库连接
                if (rs != null)
                    rs.close();

                if (connection != null)
                    connection.close();
            }
        }
    }
%>
```

如果应用系统本身通过JSON格式传参，传统的`WAF`可能无法识别，如果后端将参数进行SQL语句的拼接，则将会导致SQL注入漏洞。攻击者通过篡改JSON中对应参数的数据，达到SQL注入攻击的目的，如下图：

![img](https://oss.javasec.org/images/image-20201114130337178.png)



## 4. SQL注入 - Multipart传参测试

**示例 - 存在SQL注入漏洞的代码示例(Multipart传参方式)：**

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.fileupload.FileItemIterator" %>
<%@ page import="org.apache.commons.fileupload.FileItemStream" %>
<%@ page import="org.apache.commons.fileupload.servlet.ServletFileUpload" %>
<%@ page import="org.apache.commons.fileupload.util.Streams" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.FileOutputStream" %>
<%@ page import="org.apache.commons.fileupload.FileUploadException" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.sql.DriverManager" %>
<%@ page import="com.alibaba.fastjson.JSON" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.io.IOException" %>
<%
    //    MYSQL sys_user示例表，测试时请先创建对应的数据库和表
//
//    CREATE TABLE `sys_user` (
//        `id` int(9) unsigned NOT NULL AUTO_INCREMENT COMMENT '用户ID',
//        `username` varchar(16) NOT NULL COMMENT '用户名',
//        `password` varchar(32) NOT NULL COMMENT '用户密码',
//        `user_avatar` varchar(255) DEFAULT NULL COMMENT '用户头像',
//        `register_time` datetime DEFAULT NULL COMMENT '注册时间',
//        PRIMARY KEY (`id`),
//        UNIQUE KEY `idx_sys_user_username` (`username`) USING BTREE
//    ) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8 COMMENT='系统用户表'
//
//    INSERT INTO `sys_user` VALUES ('1', 'admin', '123456', '/res/images/avatar/default.png', '2020-05-05 17:21:27'), ('2', 'test', '123456', '/res/images/avatar/default.png', '2020-05-06 18:27:10'), ('3', 'root', '123456', '/res/images/avatar/default.png', '2020-05-06 18:28:27'), ('4', 'user', '123456', '/res/images/avatar/default.png', '2020-05-06 18:31:34'), ('5', 'rasp', '123456', '/res/images/avatar/default.png', '2020-05-06 18:32:08');
%>

<%!
    /**
     * 解析Multipart请求中的参数
     * @param request
     * @return
     */
    Map<String, String> parseMultipartContent(HttpServletRequest request) {
        Map<String, String> dataMap = new HashMap<String, String>();

        try {
            ServletFileUpload fileUpload       = new ServletFileUpload();
            FileItemIterator  fileItemIterator = fileUpload.getItemIterator(request);

            while (fileItemIterator.hasNext()) {
                FileItemStream fileItemStream = fileItemIterator.next();

                if (fileItemStream.isFormField()) {
                    // 字段名称
                    String fieldName = fileItemStream.getFieldName();

                    // 字段值
                    String fieldValue = Streams.asString(fileItemStream.openStream());

                    dataMap.put(fieldName, fieldValue);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return dataMap;
    }
%>

<%
    if (ServletFileUpload.isMultipartContent(request)) {
        Map<String, String> dataMap  = parseMultipartContent(request);
        String              username = dataMap.get("username");
        String              password = dataMap.get("password");

        // 处理用户登陆逻辑
        if (username != null && password != null) {
            ResultSet           rs         = null;
            Connection          connection = null;
            Map<String, Object> userInfo   = new HashMap<String, Object>();

            try {
                Class.forName("com.mysql.jdbc.Driver");
                connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/javaweb-bbs", "root", "root");

                String sql = "select * from sys_user where username = '" + username + "' and password = '" + password + "'";
                System.out.println(sql);

                rs = connection.prepareStatement(sql).executeQuery();

                while (rs.next()) {
                    userInfo.put("id", rs.getString("id"));
                    userInfo.put("username", rs.getString("username"));
                    userInfo.put("password", rs.getString("password"));
                    userInfo.put("user_avatar", rs.getString("user_avatar"));
                    userInfo.put("register_time", rs.getDate("register_time"));
                }

                // 检查是否登陆成功
                if (userInfo.size() > 0) {
                    // 设置用户登陆信息
                    out.println(JSON.toJSONString(userInfo));
                } else {
                    out.println("<script>alert('登陆失败，账号或密码错误!');history.back(-1)</script>");
                }
            } catch (Exception e) {
                e.printStackTrace();
                out.println("<script>alert('登陆失败，服务器异常!');history.back(-1)</script>");
            } finally {
                // 关闭数据库连接
                if (rs != null)
                    rs.close();

                if (connection != null)
                    connection.close();
            }
        }
    } else {
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>File upload</title>
</head>
<body>
<form action="" enctype="multipart/form-data" method="post">
    <p>
        Username: <input name="username" type="text" value="admin" /><br/>
        Password: <input name="password" type="text" value="'=0#" />
    </p>
    <input name="submit" type="submit" value="Submit"/>
</form>
</body>
</html>
<%
    }
%>
```

访问示例中的后台登陆地址：[http://localhost:8000/modules/jdbc/multipart.jsp](http://localhost:8000/modules/jdbc/multipart.jsp)，如下图：

![img](https://oss.javasec.org/images/image-20201114205310711.png)

提交万能密码`'=0#`即可绕过登陆验证获取到`admin`用户信息：

![img](https://oss.javasec.org/images/image-20201114210148830.png)

**Spring MVC Multipart请求解析示例**

```java
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import static org.javaweb.utils.HttpServletResponseUtils.responseHTML;

/**
 * Creator: yz
 * Date: 2020-05-04
 */
@Controller
@RequestMapping("/SQLInjection/")
public class SQLInjectionController {

    @Resource
    private JdbcTemplate jdbcTemplate;

    @RequestMapping("/Login.php")
    public void login(String username, String password, String action, String formType,
                      HttpServletRequest request, HttpServletResponse response,
                      HttpSession session) throws IOException {

        String      contentType = request.getContentType();
        String      sessionKey  = "USER_INFO";
        Object      sessionUser = session.getAttribute(sessionKey);
        PrintWriter out         = response.getWriter();

        // 退出登陆
        if (sessionUser != null && "exit".equals(action)) {
            session.removeAttribute(sessionKey);

            response.sendRedirect(request.getServletPath() + (formType != null ? "?formType=" + formType : ""));
            return;
        }

        Map<String, Object> userInfo = null;

        // 检查用户是否已经登陆成功
        if (sessionUser instanceof Map) {
            userInfo = (Map<String, Object>) sessionUser;

            responseHTML(response,
                    "<p>欢迎回来:" + userInfo.get("username") + ",ID:" +
                            userInfo.get("id") + " \r<a href='?action=exit" + (formType != null ? "&formType=" + formType : "") + "'>退出登陆</a></p>"
            );

            return;
        }

        // 处理用户登陆逻辑
        if (username != null && password != null) {
            userInfo = new HashMap<String, Object>();

            try {
                String sql = "select id,username,password from sys_user where username = '" +
                        username + "' and password = '" + password + "'";

                System.out.println(sql);

                userInfo = jdbcTemplate.queryForMap(sql);

                // 检查是否登陆成功
                if (userInfo.size() > 0) {
                    // 设置用户登陆信息
                    session.setAttribute(sessionKey, userInfo);

                    String q = request.getQueryString();

                    // 跳转到登陆成功页面
                    response.sendRedirect(request.getServletPath() + (q != null ? "?" + q : ""));
                } else {
                    responseHTML(response, "<script>alert('登陆失败，账号或密码错误!');history.back(-1)</script>");
                }
            } catch (Exception e) {
                responseHTML(response, "<script>alert('登陆失败，服务器异常!');history.back(-1)</script>");
            }

            return;
        }

        String multipartReq = "";

        // 如果传入formType=multipart参数就输出multipart表单，否则输出普通的表单
        if ("multipart".equals(formType)) {
            multipartReq = " enctype=\"multipart/form-data\" ";
        }

        responseHTML(response, "<html>\n" +
                "<head>\n" +
                "    <title>Login Test</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "<div style=\"margin: 30px;\">\n" +
                "    <form action=\"#\" " + multipartReq + " method=\"POST\">\n" +
                "        Username:<input type=\"text\" name=\"username\" value=\"admin\"/><br/>\n" +
                "        Password:<input type=\"text\" name=\"password\" value=\"'=0#\"/><br/>\n" +
                "        <input type=\"submit\" value=\"登陆\"/>\n" +
                "    </form>\n" +
                "</div>\n" +
                "</body>\n" +
                "</html>");

        out.flush();
        out.close();
    }

}
```

访问示例中的后台登陆地址：[http://localhost:8000/SQLInjection/Login.php?formType=multipart](http://localhost:8000/SQLInjection/Login.php?formType=multipart)，如下图：

![img](https://oss.javasec.org/images/image-20201114220526648.png)

发送Multipart请求，登陆测试Spring MVC：

![img](https://oss.javasec.org/images/image-20201114220814376.png)

使用万能密码登陆成功：

![img](https://oss.javasec.org/images/image-20201114220410465.png)





## 5. SQL注入修复

为了避免SQL注入攻击的产生，需要严格检查请求参数的合法性或使用预编译，请参考JDBC章节中的JDBC SQL注入防御方案。



### 5.1 RASP SQL注入防御

在Java中，所有的数据库读写操作都需要使用JDBC驱动来实现，JDBC规范中定义了数据库查询的接口，不同的数据库厂商通过实现JDBC定义的接口来实现数据库的连接、查询等操作。

RASP是基于行为的方式来实现SQL注入检测的，如果请求的参数最终并没有被数据库执行，那么RASP的SQL注入检测模块根本就不会被触发。



#### 5.1.1 java.sql.Connection/Statement接口Hook

虽然每种数据库的驱动包的类名都不一样，但是它们都必须实现JDBC接口，所以我们可以利用这一特点，使用RASP Hook JDBC数据库查询的接口类：`java.sql.Connection`、`java.sql.Statement`。

例如Mysql的驱动包的实现数据库连接的实现类是：`com.mysql.jdbc.ConnectionImpl`，该类实现了`com.mysql.jdbc.MySQLConnection`接口，而`com.mysql.jdbc.MySQLConnection`类是`java.sql.Connection`的子类，也就是说`com.mysql.jdbc.ConnectionImpl`接口必须实现`java.sql.Connection`定义的数据库连接和查询方法。

**示例 - com.mysql.jdbc.ConnectionImpl 类继承关系图：**

![img](https://oss.javasec.org/images/image-20201114173131757.png)

灵蜥内置了JDBC接口的Hook方法，如下：

**示例 - 灵蜥Hook Connection接口代码片段：**

```java
/**
 * JDBC Connection 数据库查询Hook
 * Creator: yz
 * Date: 2019-07-23
 */
@RASPClassHook
public class ConnectionHook {
  
   // 省略其他Hook方法

   /**
    * Hook java.sql.Connection接口的所有子类中的prepareStatement方法，且该方法的第一个参数必须是字符串
    */
   @RASPMethodHook(
         superClass = "java.sql.Connection", methodName = "prepareStatement",
         methodArgsDesc = "^Ljava/lang/String;.*", methodDescRegexp = true
   )
   public static class ConnectionPrepareStatementHook extends RASPMethodAdvice {

      @Override
      public RASPHookResult<?> onMethodEnter() {
         // 获取prepareStatement的第一个参数值，也就是JDBC执行的SQL语句
         String sql = (String) getArg(0);

         // 分析执行的SQL语句是否合法，并返回检测结果
         return JdbcSqlQueryHookHandler.sqlQueryHook(sql, this);
      }

   }

}
```

当`com.mysql.jdbc.ConnectionImpl`类被JVM加载后会因为配置了RASP的Agent，该类的字节码会传递到RASP的Agent处理，RASP经过分析后得出`ConnectionImpl`类符合RASP内置的`ConnectionPrepareStatementHook`类设置的Hook条件（父类名/方法名/方法参数完全匹配），那么RASP就会使用ASM动态生成防御代码并插入到被Hook的方法中。

**示例 - 未修改的ConnectionImpl类代码片段：**

```java
package com.mysql.jdbc;

public class ConnectionImpl extends ConnectionPropertiesImpl implements MySQLConnection {
  
    // 省略其他业务代码
  
    public java.sql.PreparedStatement prepareStatement(String sql) throws SQLException {
        return prepareStatement(sql, DEFAULT_RESULT_SET_TYPE, DEFAULT_RESULT_SET_CONCURRENCY);
    }
        
}
```

**示例 - 经过RASP修改后的代码片段：**

```java
package com.anbai.lingxe.agent;

import com.anbai.lingxe.loader.hooks.RASPHookHandlerType;
import com.anbai.lingxe.loader.hooks.RASPHookProxy;
import com.anbai.lingxe.loader.hooks.RASPHookResult;

import java.sql.PreparedStatement;
import java.sql.SQLException;

public class ConnectionImpl extends ConnectionPropertiesImpl implements MySQLConnection {

    // 省略其他业务代码
  
    public PreparedStatement prepareStatement(String sql) throws SQLException {
        // 生成Object数组对象，存储方法参数值
        Object[] parameters = new Object[]{sql};

        // 生成try/catch
        try {
            // 调用RASP方法方法进入时检测逻辑
            RASPHookResult enterResult = RASPHookProxy.onMethodEnter(parameters, ...);
            String HandlerType = enterResult.getRaspHookHandlerType().toString();

            if (RASPHookHandlerType.REPLACE_OR_BLOCK.toString().equals(HandlerType)) {
                // 如果RASP检测结果需要阻断或替换程序执行逻辑，return RASP返回结果中设置的返回值
                return (PreparedStatement) enterResult.getReturnValue();
            } else if (RASPHookHandlerType.THROW.toString().equals(HandlerType)) {
                // 如果RASP检测结果需要往外抛出异常，throw RASP返回结果中设置的异常对象
                throw (Throwable) enterResult.getException();
            }

            // 执行程序原逻辑，创建PreparedStatement对象
            PreparedStatement methodReturn = prepareStatement(sql, 1003, 1007);

            // 调用RASP方法方法退出时检测逻辑，同onMethodEnter，此处省略对应代码

            return methodReturn;
        } catch (Throwable t) {
            // 调用RASP方法方法异常退出时检测逻辑，同onMethodEnter，此处省略对应代码
        }
    }
}
```

增强后的`ConnectionImpl`类执行任何SQL语句都会被被RASP捕获并检测合法性，从而实现了彻底的SQL注入攻击防御。



#### 5.1.2 RASP SQL注入防御原理

RASP和WAF防御SQL注入能力有着本质上的区别，不管WAF如何的吹捧人工智能、机器学习它们都无法精确的识别SQL注入攻击，因为在WAF层面根本就无法判定传入的参数最终会不会拼接到SQL语句中，甚至连后端有没有用数据库都不知道，所以WAF的识别误报率高也就是不可避免的了。

RASP与Web应用融为了一体，可以无视Https加密、无需手动解析Http请求参数，还可以直接获取到数据库最终执行的SQL语句，在SQL注入防御能力上有着得天独厚的条件。

**示例 - RASP防御SQL注入原理：**

![img](https://oss.javasec.org/images/image-20201114190244229.png)

从上图可以看出，RASP将Hook到的SQL语句做词法解析，然后结合Http请求的参数做关联分析，得出password参数直接导致了SQL词法的语义变化，从而判定该SQL语句中包含了注入攻击，RASP会立即阻止SQL查询并阻断Http请求。

RASP通过词法解析可以得出SQL语句中使用的数据库函数、表名称、字段等关键信息，结合黑名单机制可以实现对敏感函数禁用，如：`load_file/into outfile/xp_cmdshell`等。

为了降低误判和性能，RASP可以选择性的不检测长度低于3位的参数、不检测数字型的参数等。



#### 5.1.3 基于SQL词法解析实现防御测试

灵蜥使用了SQL词法解析来检测SQL注入漏洞或攻击，对于SQL注入的检测能力精确而有效，比如可以轻松的识别出函数和算数运算类的SQL注入攻击，如图：

![img](https://oss.javasec.org/images/image-20201114192036707.png)

RASP可以识别出参数id中的`100001-1`会在数据库中做算术运算，因为会被RASP拦截，通常攻击者非常喜欢使用这种方式来探测是否存在SQL注入，传统的WAF因为根本识别这个参数的具体业务含义，从而无法识别此类SQL注入攻击。

#### 5.1.4 RASP对JSON、Multipart请求的支持

处理传统的GET/POST参数传递以外，`json`、`multipart`和`web service`是目前后端开发最为常用的参数传递方式，标准的Web容器默认是不会解析这几类请求参数的，而主流的MVC框架（如：`Spring MVC`）具备了解析这几类请求参数的能力。



**示例 - Multipart请求拦截：**

![img](https://oss.javasec.org/images/image-20201114210656031.png)

**示例 - JSON请求拦截：**

![img](https://oss.javasec.org/images/image-20201114210928260.png)