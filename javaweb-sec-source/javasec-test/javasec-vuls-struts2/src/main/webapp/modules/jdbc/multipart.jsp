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