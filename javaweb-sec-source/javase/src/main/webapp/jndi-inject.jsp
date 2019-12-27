<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.sun.rowset.JdbcRowSetImpl" %>
<%
    JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
    jdbcRowSet.setDataSourceName(request.getParameter("url"));
    jdbcRowSet.setAutoCommit(true);
%>