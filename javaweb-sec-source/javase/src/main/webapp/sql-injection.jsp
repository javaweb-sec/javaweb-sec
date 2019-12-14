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
    public static final String URL = "jdbc:mysql://localhost:3306/mysql?autoReconnect=true&zeroDateTimeBehavior=round&useUnicode=true&characterEncoding=UTF-8&useOldAliasMetadataBehavior=true&useOldAliasMetadataBehavior=true&useSSL=false&useServerPrepStmts=false";

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
