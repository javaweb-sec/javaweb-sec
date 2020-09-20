<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>

<pre>
<%
    String[] files = new File(request.getParameter("dir")).list();

    for (String file : files) {
        out.println(file);
    }
%>
</pre>