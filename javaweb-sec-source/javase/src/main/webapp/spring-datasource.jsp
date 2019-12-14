<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.springframework.context.ApplicationContext" %>
<%@ page import="org.springframework.web.context.support.WebApplicationContextUtils" %>
<%@ page import="javax.sql.DataSource" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.PreparedStatement" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.sql.ResultSetMetaData" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.lang.reflect.InvocationTargetException" %>
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
    // C3PO数据源类
    private static final String C3P0_CLASS_NAME = "com.mchange.v2.c3p0.ComboPooledDataSource";

    // DBCP数据源类
    private static final String DBCP_CLASS_NAME = "org.apache.commons.dbcp.BasicDataSource";

    //Druid数据源类
    private static final String DRUID_CLASS_NAME = "com.alibaba.druid.pool.DruidDataSource";

    /**
     * 获取所有Spring管理的数据源
     * @param ctx Spring上下文
     * @return 数据源数组
     */
    List<DataSource> getDataSources(ApplicationContext ctx) {
        List<DataSource> dataSourceList = new ArrayList<DataSource>();
        String[]         beanNames      = ctx.getBeanDefinitionNames();

        for (String beanName : beanNames) {
            Object object = ctx.getBean(beanName);

            if (object instanceof DataSource) {
                dataSourceList.add((DataSource) object);
            }
        }

        return dataSourceList;
    }

    /**
     * 打印Spring的数据源配置信息,当前只支持DBCP/C3P0/Druid数据源类
     * @param ctx Spring上下文对象
     * @return 数据源配置字符串
     * @throws ClassNotFoundException 数据源类未找到异常
     * @throws NoSuchMethodException 反射调用时方法没找到异常
     * @throws InvocationTargetException 反射调用异常
     * @throws IllegalAccessException 反射调用时不正确的访问异常
     */
    String printDataSourceConfig(ApplicationContext ctx) throws ClassNotFoundException,
            NoSuchMethodException, InvocationTargetException, IllegalAccessException {

        List<DataSource> dataSourceList = getDataSources(ctx);

        for (DataSource dataSource : dataSourceList) {
            String className = dataSource.getClass().getName();
            String url       = null;
            String UserName  = null;
            String PassWord  = null;

            if (C3P0_CLASS_NAME.equals(className)) {
                Class clazz = Class.forName(C3P0_CLASS_NAME);
                url = (String) clazz.getMethod("getJdbcUrl").invoke(dataSource);
                UserName = (String) clazz.getMethod("getUser").invoke(dataSource);
                PassWord = (String) clazz.getMethod("getPassword").invoke(dataSource);
            } else if (DBCP_CLASS_NAME.equals(className)) {
                Class clazz = Class.forName(DBCP_CLASS_NAME);
                url = (String) clazz.getMethod("getUrl").invoke(dataSource);
                UserName = (String) clazz.getMethod("getUsername").invoke(dataSource);
                PassWord = (String) clazz.getMethod("getPassword").invoke(dataSource);
            } else if (DRUID_CLASS_NAME.equals(className)) {
                Class clazz = Class.forName(DRUID_CLASS_NAME);
                url = (String) clazz.getMethod("getUrl").invoke(dataSource);
                UserName = (String) clazz.getMethod("getUsername").invoke(dataSource);
                PassWord = (String) clazz.getMethod("getPassword").invoke(dataSource);
            }

            return "URL:" + url + "<br/>UserName:" + UserName + "<br/>PassWord:" + PassWord + "<br/>";
        }

        return null;
    }
%>
<%
    String sql = request.getParameter("sql");// 定义需要执行的SQL语句

    // 获取Spring的ApplicationContext对象
    ApplicationContext ctx = WebApplicationContextUtils.getWebApplicationContext(pageContext.getServletContext());

    // 获取Spring中所有的数据源对象
    List<DataSource> dataSourceList = getDataSources(ctx);

    // 检查是否获取到了数据源
    if (dataSourceList == null) {
        out.println("未找到任何数据源配置信息!");
        return;
    }

    out.println("<hr/>");
    out.println("Spring DataSource配置信息获取测试:");
    out.println("<hr/>");
    out.print(printDataSourceConfig(ctx));
    out.println("<hr/>");

    // 定义需要查询的SQL语句
    sql = sql != null ? sql : "select version()";

    for (DataSource dataSource : dataSourceList) {
        out.println("<hr/>");
        out.println("SQL语句:<font color='red'>" + sql + "</font>");
        out.println("<hr/>");

        //从数据源中获取数据库连接对象
        Connection connection = dataSource.getConnection();

        // 创建预编译查询对象
        PreparedStatement pstt = connection.prepareStatement(sql);

        // 执行查询并获取查询结果对象
        ResultSet rs = pstt.executeQuery();

        out.println("<table><tr>");

        // 获取查询结果的元数据对象
        ResultSetMetaData metaData = rs.getMetaData();

        // 从元数据中获取字段信息
        for (int i = 1; i <= metaData.getColumnCount(); i++) {
            out.println("<th>" + metaData.getColumnName(i) + "(" + metaData.getColumnTypeName(i) + ")\t" + "</th>");
        }

        out.println("<tr/>");

        // 获取JDBC查询结果
        while (rs.next()) {
            out.println("<tr>");

            for (int i = 1; i <= metaData.getColumnCount(); i++) {
                out.println("<td>" + rs.getObject(metaData.getColumnName(i)) + "</td>");
            }

            out.println("<tr/>");
        }

        rs.close();
        pstt.close();
    }
%>