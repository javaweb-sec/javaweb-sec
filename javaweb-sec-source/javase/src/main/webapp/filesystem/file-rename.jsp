<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%
    String fileName1 = request.getParameter("s");
    String fileName2 = request.getParameter("d");

    File f = new File(fileName1);
    File d = new File(fileName2);

    f.renameTo(d);

    out.println(d + "\t" + d.exists());
%>