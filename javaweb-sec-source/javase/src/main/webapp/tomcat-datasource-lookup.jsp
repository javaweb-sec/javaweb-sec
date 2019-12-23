<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="javax.naming.Context" %>
<%@ page import="javax.naming.InitialContext" %>
<%@ page import="javax.sql.DataSource" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.ResultSet" %>
<%
    // 初始化JNDIContext
    Context context = new InitialContext();

    // 搜索Tomcat注册的JNDI数据库连接池对象
    DataSource dataSource = (DataSource) context.lookup("java:comp/env/jdbc/test");

    // 获取数据库连接
    Connection connection = dataSource.getConnection();

    // 查询SQL语句并返回结果
    ResultSet rs = connection.prepareStatement("select version()").executeQuery();

    // 获取数据库查询结果
    while (rs.next()) {
        out.println(rs.getObject(1));
    }

    rs.close();
%>