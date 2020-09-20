<%@page contentType="text/html" pageEncoding="UTF-8" %>
<%@ page import="java.util.Map" %>
<pre>
<%
    out.println(request.getParameter("id"));
    out.println("-------------------------------------------------");
    out.println(this.getClass().getClassLoader());
    out.println("-------------------------------------------------");
    Map<String, String> map = System.getenv();

    for (String k : map.keySet()) {
        out.println(k + ":" + map.get(k));
    }
%>
</pre>