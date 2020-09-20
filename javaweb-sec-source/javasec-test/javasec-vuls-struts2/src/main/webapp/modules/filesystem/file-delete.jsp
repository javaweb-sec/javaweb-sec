<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%
    File file = new File(request.getParameter("file"));
    out.println(file.delete());
%>