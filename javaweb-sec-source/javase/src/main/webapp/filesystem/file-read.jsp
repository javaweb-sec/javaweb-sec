<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.io.IOUtils" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.FileInputStream" %>
<%@ page import="java.io.IOException" %>

<%
    try {
        FileInputStream fis = new FileInputStream(new File(request.getParameter("file")));
        IOUtils.copy(fis, out);
        fis.close();
    } catch (IOException e) {
        out.println(e.toString());
    }
%>