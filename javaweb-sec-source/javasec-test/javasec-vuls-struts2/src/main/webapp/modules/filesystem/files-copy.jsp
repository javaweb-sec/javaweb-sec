<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.nio.file.Path" %>
<%@ page import="java.nio.file.Paths" %>
<pre>
<%
    try {
        Path path = Files.copy(Paths.get(request.getParameter("source")), Paths.get(request.getParameter("dest")));

        out.println(path);
    } catch (IOException e) {
        e.printStackTrace();
    }
%>
</pre>