<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.nio.file.Paths" %>
<pre>
<%
    try {
        byte[] bytes = Files.readAllBytes(Paths.get(request.getParameter("file")));
        out.println(new String(bytes));
    } catch (IOException e) {
        e.printStackTrace();
    }
%>
</pre>